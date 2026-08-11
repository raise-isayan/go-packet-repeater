package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pion/dtls/v3"

	"gopr/internal/config"
	"gopr/internal/logx"
)

// writeLeafCert generates a self-signed, non-CA leaf certificate (with
// embedded private key) valid for 127.0.0.1, matching the -cert= format
// gopr expects.
func writeLeafCert(t *testing.T, dir string) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	var data []byte
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)

	p := filepath.Join(dir, "leaf.pem")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// freeUDPPort returns a currently-unused UDP port on 127.0.0.1 by briefly
// binding to port 0 and closing again.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("finding a free UDP port: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

// runPlaintextUDPEcho starts a plain UDP echo server on addr, stopped when
// ctx is cancelled.
func runPlaintextUDPEcho(t *testing.T, ctx context.Context, addr string) {
	t.Helper()
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("resolving %s: %v", addr, err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		t.Fatalf("listening on %s: %v", addr, err)
	}
	go func() {
		<-ctx.Done()
		conn.Close()
	}()
	go func() {
		buf := make([]byte, 1024)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			conn.WriteToUDP(buf[:n], from)
		}
	}()
}

// runDTLSEcho starts a DTLS echo server on addr using certPath, stopped
// when ctx is cancelled.
func runDTLSEcho(t *testing.T, ctx context.Context, addr, certPath string) {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(certPath, certPath)
	if err != nil {
		t.Fatalf("loading cert: %v", err)
	}
	laddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("resolving %s: %v", addr, err)
	}
	ln, err := dtls.Listen("udp", laddr, &dtls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("dtls.Listen on %s: %v", addr, err)
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if _, err := c.Write(buf[:n]); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
}

// dialDTLSWithRetry dials addr with DTLS, retrying briefly to absorb the
// race between the server goroutine starting and its listener binding.
func dialDTLSWithRetry(t *testing.T, addr string, cfg *dtls.Config) net.Conn {
	t.Helper()
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatalf("resolving %s: %v", addr, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := dtls.Dial("udp", raddr, cfg)
		if err == nil {
			return conn
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("dialing DTLS %s: %v", addr, lastErr)
	return nil
}

func TestServeUDPDTLSDecodeOnly(t *testing.T) {
	dir := t.TempDir()
	certPath := writeLeafCert(t, dir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	targetAddr := fmt.Sprintf("127.0.0.1:%d", freeUDPPort(t))
	runPlaintextUDPEcho(t, ctx, targetAddr)

	listenAddr := fmt.Sprintf("127.0.0.1:%d", freeUDPPort(t))
	cfg := &config.Config{
		Listen:   config.Endpoint{Addr: listenAddr, UDP: true, SSL: true},
		Target:   config.Endpoint{Addr: targetAddr, UDP: true},
		CertPath: certPath,
		Verify:   true,
	}
	go serveUDPDTLS(ctx, cfg, logx.New(logx.LevelDebug, false))

	conn := dialDTLSWithRetry(t, listenAddr, &dtls.Config{InsecureSkipVerify: true})
	defer conn.Close()

	payload := []byte("hello over dtls")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Errorf("echoed payload = %q, want %q", buf[:n], payload)
	}
}

func TestServeUDPDTLSBothSides(t *testing.T) {
	dir := t.TempDir()
	certPath := writeLeafCert(t, dir)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	targetAddr := fmt.Sprintf("127.0.0.1:%d", freeUDPPort(t))
	runDTLSEcho(t, ctx, targetAddr, certPath)

	listenAddr := fmt.Sprintf("127.0.0.1:%d", freeUDPPort(t))
	cfg := &config.Config{
		Listen:   config.Endpoint{Addr: listenAddr, UDP: true, SSL: true},
		Target:   config.Endpoint{Addr: targetAddr, UDP: true, SSL: true},
		CertPath: certPath,
		Verify:   false,
	}
	go serveUDPDTLS(ctx, cfg, logx.New(logx.LevelDebug, false))

	conn := dialDTLSWithRetry(t, listenAddr, &dtls.Config{InsecureSkipVerify: true})
	defer conn.Close()

	payload := []byte("hello over double dtls")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Errorf("echoed payload = %q, want %q", buf[:n], payload)
	}
}
