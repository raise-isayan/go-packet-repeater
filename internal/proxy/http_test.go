package proxy

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"gopr/internal/config"
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
