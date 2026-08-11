// Package proxy implements gopr's "proxy" (HTTP) and "socks" (SOCKS5)
// modes.
package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"gopr/internal/config"
	"gopr/internal/logx"
)

// RunHTTP starts an HTTP proxy on cfg.Listen.Addr. It supports plain HTTP
// forward requests as well as CONNECT tunneling for HTTPS. Per SKILL.md,
// "proxy" mode is HTTP-only: it never performs TLS termination itself.
// cfg.LogLevel/cfg.Verbose select diagnostic detail and data dumping (-d/-v),
// same as forwarding mode.
func RunHTTP(ctx context.Context, cfg *config.Config) error {
	log := logx.New(logx.Level(cfg.LogLevel), cfg.Verbose)
	addr := cfg.Listen.Addr

	srv := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleConnect(w, r, log)
				return
			}
			handleForward(w, r, log)
		}),
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	log.Print("http proxy: listening on %s", addr)
	err := srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// handleConnect tunnels an HTTPS (or other TCP) connection through a
// CONNECT request without decrypting it.
func handleConnect(w http.ResponseWriter, r *http.Request, log *logx.Logger) {
	label := fmt.Sprintf("http-connect %s", r.Host)
	log.Warn("%s: request from %s", label, r.RemoteAddr)
	start := time.Now()

	dst, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		log.Error("http-connect: %s: dial: %v", r.Host, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer dst.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	src, buf, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer src.Close()

	if _, err := buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buf.Flush(); err != nil {
		return
	}
	log.Info("%s: connected to %s", label, r.Host)

	var wg sync.WaitGroup
	var sent, recv int64
	wg.Add(2)
	go func() { defer wg.Done(); sent, _ = logx.Copy(log, label, true, dst, buf) }()
	go func() { defer wg.Done(); recv, _ = logx.Copy(log, label, false, src, dst) }()
	wg.Wait()

	if log.InfoEnabled() {
		log.Info("%s: closed (sent=%d recv=%d duration=%s)", label, sent, recv, time.Since(start).Round(time.Millisecond))
	} else {
		log.Warn("%s: closed", label)
	}
}

// hopByHopHeaders are stripped before forwarding a proxied request/response,
// per RFC 7230 6.1.
var hopByHopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// handleForward proxies a plain (non-CONNECT) HTTP request to its
// destination and copies the response back.
func handleForward(w http.ResponseWriter, r *http.Request, log *logx.Logger) {
	if !r.URL.IsAbs() {
		http.Error(w, "proxy: request URI must be absolute", http.StatusBadRequest)
		return
	}

	label := fmt.Sprintf("http %s %s", r.Method, r.URL)
	log.Warn("%s: request from %s", label, r.RemoteAddr)

	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	for _, h := range hopByHopHeaders {
		outReq.Header.Del(h)
	}

	resp, err := http.DefaultTransport.RoundTrip(outReq)
	if err != nil {
		log.Error("http: %s: %v", label, err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	log.Info("%s: %s", label, resp.Status)

	for _, h := range hopByHopHeaders {
		resp.Header.Del(h)
	}
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	logx.Copy(log, label, false, w, resp.Body)
}
