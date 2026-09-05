package proxy

import (
	"io"
	"net"
	"strings"
	"testing"

	"gopr/internal/config"
)

// startFakeSOCKSUpstream runs a minimal SOCKS5 server for one connection,
// selecting username/password auth (RFC 1929) whenever wantUser is
// non-empty and "no authentication" otherwise, matching dialUpstreamSOCKS's
// own method-selection logic. It accepts the auth (or not, gated by
// authOK) and always replies "succeeded" to the following CONNECT.
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

		hdr := make([]byte, 2)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		methods := make([]byte, hdr[1])
		if _, err := io.ReadFull(conn, methods); err != nil {
			return
		}
		method := byte(socksAuthNone)
		if wantUser != "" {
			method = socksAuthUserPass
		}
		if _, err := conn.Write([]byte{socksVersion5, method}); err != nil {
			return
		}

		if method == socksAuthUserPass {
			vh := make([]byte, 2)
			if _, err := io.ReadFull(conn, vh); err != nil {
				return
			}
			u := make([]byte, vh[1])
			if _, err := io.ReadFull(conn, u); err != nil {
				return
			}
			pl := make([]byte, 1)
			if _, err := io.ReadFull(conn, pl); err != nil {
				return
			}
			p := make([]byte, pl[0])
			if _, err := io.ReadFull(conn, p); err != nil {
				return
			}
			status := byte(0)
			if !authOK || string(u) != wantUser || string(p) != wantPass {
				status = 1
			}
			if _, err := conn.Write([]byte{socksUserPassVersion, status}); err != nil {
				return
			}
			if status != 0 {
				return
			}
		}

		rh := make([]byte, 4)
		if _, err := io.ReadFull(conn, rh); err != nil {
			return
		}
		switch rh[3] {
		case socksAtypDomain:
			l := make([]byte, 1)
			if _, err := io.ReadFull(conn, l); err != nil {
				return
			}
			if _, err := io.ReadFull(conn, make([]byte, l[0])); err != nil {
				return
			}
		case socksAtypIPv4:
			if _, err := io.ReadFull(conn, make([]byte, 4)); err != nil {
				return
			}
		case socksAtypIPv6:
			if _, err := io.ReadFull(conn, make([]byte, 16)); err != nil {
				return
			}
		}
		if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
			return
		}
		conn.Write([]byte{socksVersion5, socksReplySucceeded, 0, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
	}()

	return ln.Addr().String()
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
