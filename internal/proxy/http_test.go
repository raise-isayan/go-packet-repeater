package proxy

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"gopr/internal/config"
	"gopr/internal/logx"
)

func TestDialUpstreamConnectAuth(t *testing.T) {
	run := func(t *testing.T, auth config.ForwardAuthConfig, want string) {
		t.Helper()
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()

		gotHeader := make(chan string, 1)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			req, err := http.ReadRequest(bufio.NewReader(conn))
			if err != nil {
				return
			}
			gotHeader <- req.Header.Get("Proxy-Authorization")
			conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		}()

		conn, err := dialUpstreamConnect(ln.Addr().String(), "example.com:443", auth)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer conn.Close()

		select {
		case got := <-gotHeader:
			if got != want {
				t.Errorf("Proxy-Authorization = %q, want %q", got, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for upstream request")
		}
	}

	t.Run("with credentials sends Basic auth header", func(t *testing.T) {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:s3cret"))
		run(t, config.ForwardAuthConfig{User: "alice", Pass: "s3cret"}, want)
	})

	t.Run("without credentials sends no auth header", func(t *testing.T) {
		run(t, config.ForwardAuthConfig{}, "")
	})
}

// startFakeSOCKSUpstreamEcho runs a minimal no-auth SOCKS5 server for one
// connection: it accepts any CONNECT, replies "succeeded", then echoes
// whatever bytes follow. Used to test handleConnect's
// backendKind == config.ModeSOCKSProxy path (an HTTP-proxy frontend
// chained to a SOCKS backend; see RunHTTP's "Proxy変換" doc comment).
func startFakeSOCKSUpstreamEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if !fakeSOCKSHandshakeAndConnect(conn, "", "", true) {
			return
		}
		// A single bounded read/write, not an unbounded io.Copy: the test
		// sends one message and expects it echoed back, then the caller's
		// relay loop needs this side to actually close (sending a FIN) so
		// its own EOF-driven teardown completes instead of hanging forever
		// waiting for more data that will never come.
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		conn.Write(buf[:n])
	}()

	return ln.Addr().String()
}

// startFakeSOCKSUpstreamHTTP runs a minimal no-auth SOCKS5 server for one
// connection: it accepts any CONNECT, replies "succeeded", then reads one
// HTTP request over the tunnel and replies with a canned 200 response.
// Used to test newSOCKSBackedTransport, which must dial through it (rather
// than connecting directly) when RunHTTP's plain (non-CONNECT) forwarding
// is chained to a SOCKS backend.
func startFakeSOCKSUpstreamHTTP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if !fakeSOCKSHandshakeAndConnect(conn, "", "", true) {
			return
		}
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		req.Body.Close()
		conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	}()

	return ln.Addr().String()
}

// TestHandleConnectBackendKindSOCKS exercises RunHTTP's frontend/backend
// conversion (SKILL.md "Proxy変換"): an HTTP-proxy client CONNECTs to
// handleConnect as always, but backendKind == config.ModeSOCKSProxy routes
// the tunnel through an upstream SOCKS server (dialUpstreamSOCKS) instead
// of an upstream HTTP proxy, proven end-to-end by round-tripping real bytes
// through the whole chain.
func TestHandleConnectBackendKindSOCKS(t *testing.T) {
	upstream := startFakeSOCKSUpstreamEcho(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleConnect(w, r, logx.New(0, false), upstream, config.ModeSOCKSProxy, config.ForwardAuthConfig{})
	}))
	defer srv.Close()

	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echoed = %q, want %q", buf, "ping")
	}
}

// TestSOCKSBackedTransport confirms newSOCKSBackedTransport actually routes
// through the given upstream SOCKS server rather than dialing directly:
// example.com is unreachable in the test sandbox, so a real HTTP round trip
// only succeeds by going through startFakeSOCKSUpstreamHTTP.
func TestSOCKSBackedTransport(t *testing.T) {
	upstream := startFakeSOCKSUpstreamHTTP(t)
	transport := newSOCKSBackedTransport(upstream, config.ForwardAuthConfig{})

	req, err := http.NewRequest(http.MethodGet, "http://example.com/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Fatalf("body = %q, want %q", body, "ok")
	}
}

// digestChallengeResponse is a canned 407 response offering Digest auth,
// with Connection: close so the client's retry lands on a fresh connection
// (as a real upstream typically does after rejecting the first attempt).
const digestChallengeResponse = "HTTP/1.1 407 Proxy Authentication Required\r\n" +
	`Proxy-Authenticate: Digest realm="test", nonce="n0nce123", qop="auth"` + "\r\n" +
	"Connection: close\r\nContent-Length: 0\r\n\r\n"

// verifyDigestHeader asserts that header is a well-formed "Digest ..."
// Proxy-Authorization value that correctly authenticates user/pass for
// method+uri, by independently recomputing the expected response.
func verifyDigestHeader(t *testing.T, header, method, uri, user, pass string) {
	t.Helper()
	scheme, rest, _ := strings.Cut(header, " ")
	if !strings.EqualFold(scheme, "Digest") {
		t.Fatalf("Proxy-Authorization scheme = %q, want Digest", scheme)
	}
	params := map[string]string{}
	for _, p := range splitAuthParams(rest) {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			continue
		}
		params[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
	}
	if params["username"] != user {
		t.Fatalf("username = %q, want %q", params["username"], user)
	}
	if params["uri"] != uri {
		t.Fatalf("uri = %q, want %q", params["uri"], uri)
	}
	ha1 := md5Hex(user + ":" + params["realm"] + ":" + pass)
	ha2 := md5Hex(method + ":" + params["uri"])
	want := md5Hex(strings.Join([]string{ha1, params["nonce"], params["nc"], params["cnonce"], params["qop"], ha2}, ":"))
	if params["response"] != want {
		t.Fatalf("response = %q, want %q", params["response"], want)
	}
}

func TestDialUpstreamConnectAuthDigestFallback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	gotHeader := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
			conn.Close()
			return
		}
		conn.Write([]byte(digestChallengeResponse))
		conn.Close()

		conn2, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn2.Close()
		req2, err := http.ReadRequest(bufio.NewReader(conn2))
		if err != nil {
			return
		}
		gotHeader <- req2.Header.Get("Proxy-Authorization")
		conn2.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	}()

	auth := config.ForwardAuthConfig{User: "alice", Pass: "s3cret"}
	conn, err := dialUpstreamConnect(ln.Addr().String(), "example.com:443", auth)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer conn.Close()

	select {
	case got := <-gotHeader:
		verifyDigestHeader(t, got, http.MethodConnect, "example.com:443", "alice", "s3cret")
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream retry")
	}
}

func TestUpstreamAuthTransportDigestFallback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	gotHeader := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
			conn.Close()
			return
		}
		conn.Write([]byte(digestChallengeResponse))
		conn.Close()

		conn2, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn2.Close()
		req2, err := http.ReadRequest(bufio.NewReader(conn2))
		if err != nil {
			return
		}
		gotHeader <- req2.Header.Get("Proxy-Authorization")
		conn2.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
	}()

	transport := &upstreamAuthTransport{
		inner: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: ln.Addr().String()})},
		auth:  config.ForwardAuthConfig{User: "alice", Pass: "s3cret"},
	}

	req, err := http.NewRequest(http.MethodGet, "http://example.com/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Fatalf("body = %q, want %q", body, "ok")
	}

	select {
	case got := <-gotHeader:
		verifyDigestHeader(t, got, http.MethodGet, "http://example.com/path", "alice", "s3cret")
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream retry")
	}
}
