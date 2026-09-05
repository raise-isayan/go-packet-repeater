package proxy

import (
	"bufio"
	"encoding/base64"
	"net"
	"net/http"
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
