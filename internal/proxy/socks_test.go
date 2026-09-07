package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"gopr/internal/config"
	"gopr/internal/logx"
)

// fakeSOCKSHandshakeAndConnect drives the server side of a SOCKS5
// method-selection handshake and CONNECT request on conn, selecting
// username/password auth (RFC 1929) whenever wantUser is non-empty and "no
// authentication" otherwise, matching dialUpstreamSOCKS's own
// method-selection logic. It accepts the auth (or not, gated by authOK)
// and, on success, replies "succeeded" to the CONNECT and returns true,
// leaving conn positioned at the start of the tunneled byte stream ready
// for the caller to relay or serve. Shared by startFakeSOCKSUpstream (which
// stops there) and the SOCKS-backed-transport helpers in http_test.go
// (which keep going).
func fakeSOCKSHandshakeAndConnect(conn net.Conn, wantUser, wantPass string, authOK bool) bool {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return false
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return false
	}
	method := byte(socksAuthNone)
	if wantUser != "" {
		method = socksAuthUserPass
	}
	if _, err := conn.Write([]byte{socksVersion5, method}); err != nil {
		return false
	}

	if method == socksAuthUserPass {
		vh := make([]byte, 2)
		if _, err := io.ReadFull(conn, vh); err != nil {
			return false
		}
		u := make([]byte, vh[1])
		if _, err := io.ReadFull(conn, u); err != nil {
			return false
		}
		pl := make([]byte, 1)
		if _, err := io.ReadFull(conn, pl); err != nil {
			return false
		}
		p := make([]byte, pl[0])
		if _, err := io.ReadFull(conn, p); err != nil {
			return false
		}
		status := byte(0)
		if !authOK || string(u) != wantUser || string(p) != wantPass {
			status = 1
		}
		if _, err := conn.Write([]byte{socksUserPassVersion, status}); err != nil {
			return false
		}
		if status != 0 {
			return false
		}
	}

	rh := make([]byte, 4)
	if _, err := io.ReadFull(conn, rh); err != nil {
		return false
	}
	switch rh[3] {
	case socksAtypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return false
		}
		if _, err := io.ReadFull(conn, make([]byte, l[0])); err != nil {
			return false
		}
	case socksAtypIPv4:
		if _, err := io.ReadFull(conn, make([]byte, 4)); err != nil {
			return false
		}
	case socksAtypIPv6:
		if _, err := io.ReadFull(conn, make([]byte, 16)); err != nil {
			return false
		}
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		return false
	}
	if _, err := conn.Write([]byte{socksVersion5, socksReplySucceeded, 0, socksAtypIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		return false
	}
	return true
}

// startFakeSOCKSUpstream runs a minimal SOCKS5 server for one connection
// (see fakeSOCKSHandshakeAndConnect) and closes once it has replied to the
// CONNECT.
func startFakeSOCKSUpstream(t *testing.T, wantUser, wantPass string, authOK bool) string {
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
		fakeSOCKSHandshakeAndConnect(conn, wantUser, wantPass, authOK)
	}()

	return ln.Addr().String()
}

// startFakeHTTPConnectUpstreamEcho runs a minimal HTTP-CONNECT upstream for
// one connection: it accepts any CONNECT, replies 200, then echoes whatever
// bytes follow. Used to test handleSOCKSConn's backendKind == ModeHTTPProxy
// path (a SOCKS frontend chained to an HTTP-proxy backend; see RunSOCKS's
// "Proxy変換" doc comment), which must dial via dialUpstreamConnect (in
// http.go) instead of dialUpstreamSOCKS.
func startFakeHTTPConnectUpstreamEcho(t *testing.T) string {
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
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil || req.Method != http.MethodConnect {
			return
		}
		if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return
		}
		// A single bounded read/write, not an unbounded io.Copy: the test
		// sends one message and expects it echoed back, then this side
		// needs to actually close (sending a FIN) so pipeSOCKS's EOF-driven
		// teardown completes instead of hanging forever waiting for more
		// data that will never come.
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		conn.Write(buf[:n])
	}()

	return ln.Addr().String()
}

// TestHandleSOCKSConnBackendKindProxy exercises RunSOCKS's frontend/backend
// conversion (SKILL.md "Proxy変換"): a SOCKS5 client talks to
// handleSOCKSConn as always, but backendKind == ModeHTTPProxy routes the
// CONNECT through an upstream HTTP proxy (dialUpstreamConnect) instead of
// an upstream SOCKS server, proven end-to-end by round-tripping real bytes
// through the whole chain.
func TestHandleSOCKSConnBackendKindProxy(t *testing.T) {
	upstream := startFakeHTTPConnectUpstreamEcho(t)

	client, server := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		handleSOCKSConn(server, logx.New(0, false), upstream, config.ModeHTTPProxy, config.ForwardAuthConfig{})
		close(done)
	}()

	if _, err := client.Write([]byte{socksVersion5, 1, socksAuthNone}); err != nil {
		t.Fatal(err)
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(client, greet); err != nil {
		t.Fatal(err)
	}
	if greet[0] != socksVersion5 || greet[1] != socksAuthNone {
		t.Fatalf("greeting reply = %v, want [5 0]", greet)
	}

	host := "example.com"
	req := []byte{socksVersion5, socksCmdConnect, 0x00, socksAtypDomain, byte(len(host))}
	req = append(req, host...)
	req = append(req, 0x01, 0xBB) // port 443
	if _, err := client.Write(req); err != nil {
		t.Fatal(err)
	}

	reply := make([]byte, 4)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != socksReplySucceeded {
		t.Fatalf("SOCKS reply code = %d, want succeeded", reply[1])
	}
	if _, err := io.ReadFull(client, make([]byte, 6)); err != nil { // BND.ADDR/PORT
		t.Fatal(err)
	}

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echoed = %q, want %q", buf, "ping")
	}

	client.Close()
	<-done
}

func TestDialUpstreamSOCKSAuth(t *testing.T) {
	t.Run("successful username/password auth", func(t *testing.T) {
		addr := startFakeSOCKSUpstream(t, "alice", "s3cret", true)
		conn, err := dialUpstreamSOCKS(addr, "example.com:80", config.ForwardAuthConfig{User: "alice", Pass: "s3cret"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		conn.Close()
	})

	t.Run("rejected credentials is an error", func(t *testing.T) {
		addr := startFakeSOCKSUpstream(t, "alice", "s3cret", true)
		if _, err := dialUpstreamSOCKS(addr, "example.com:80", config.ForwardAuthConfig{User: "alice", Pass: "wrong"}); err == nil {
			t.Fatal("expected error for rejected credentials")
		}
	})

	t.Run("no auth still works", func(t *testing.T) {
		addr := startFakeSOCKSUpstream(t, "", "", true)
		conn, err := dialUpstreamSOCKS(addr, "example.com:80", config.ForwardAuthConfig{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		conn.Close()
	})

	t.Run("over-length username is rejected before subnegotiation", func(t *testing.T) {
		addr := startFakeSOCKSUpstream(t, "x", "y", true)
		longUser := strings.Repeat("a", 256)
		if _, err := dialUpstreamSOCKS(addr, "example.com:80", config.ForwardAuthConfig{User: longUser, Pass: "y"}); err == nil {
			t.Fatal("expected error for over-length username")
		}
	})
}
