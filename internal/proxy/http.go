// Package proxy implements gopr's "proxy" (HTTP) and "socks" (SOCKS5)
// modes.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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
//
// When cfg.UpstreamAddr is set (<target> was "<host:port>/proxy"), every
// request is relayed through that upstream HTTP proxy instead of being
// dialed directly: a CONNECT is issued to the upstream for tunneled
// requests, and plain requests are sent via an http.Transport configured
// with the upstream as its Proxy. cfg.ForwardAuth (-F -user=), when set,
// presents credentials to that upstream proxy: HTTP Basic preemptively, and
// Digest (RFC 2617) if the upstream challenges with a 407 asking for it --
// see upstreamAuthTransport and dialUpstreamConnect.
func RunHTTP(ctx context.Context, cfg *config.Config) error {
	log := logx.New(logx.Level(cfg.LogLevel), cfg.Verbose)
	addr := cfg.Listen.Addr
	upstream := cfg.UpstreamAddr
	auth := cfg.ForwardAuth

	transport := http.DefaultTransport
	if upstream != "" {
		proxyURL := &url.URL{Scheme: "http", Host: upstream}
		inner := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
		if auth.User != "" {
			transport = &upstreamAuthTransport{inner: inner, auth: auth}
		} else {
			transport = inner
		}
	}

	srv := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleConnect(w, r, log, upstream, auth)
				return
			}
			handleForward(w, r, log, transport)
		}),
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	if upstream != "" {
		log.Print("http proxy: listening on %s, forwarding via upstream proxy %s", addr, upstream)
	} else {
		log.Print("http proxy: listening on %s", addr)
	}
	err := srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// handleConnect tunnels an HTTPS (or other TCP) connection through a
// CONNECT request without decrypting it. When upstream is non-empty, the
// tunnel is established via an upstream HTTP proxy (see dialUpstreamConnect)
// instead of dialing r.Host directly, presenting auth's credentials if set.
func handleConnect(w http.ResponseWriter, r *http.Request, log *logx.Logger, upstream string, auth config.ForwardAuthConfig) {
	label := fmt.Sprintf("http-connect %s", r.Host)
	log.Warn("%s: request from %s", label, r.RemoteAddr)
	start := time.Now()

	var dst net.Conn
	var err error
	if upstream != "" {
		dst, err = dialUpstreamConnect(upstream, r.Host, auth)
	} else {
		dst, err = net.DialTimeout("tcp", r.Host, 10*time.Second)
	}
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
// destination and copies the response back, using transport (either
// http.DefaultTransport for direct dialing, or an http.Transport pointed
// at an upstream proxy -- see RunHTTP).
func handleForward(w http.ResponseWriter, r *http.Request, log *logx.Logger, transport http.RoundTripper) {
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

	resp, err := transport.RoundTrip(outReq)
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

// upstreamAuthTransport wraps an http.RoundTripper that sends plain
// (non-CONNECT) requests through an upstream HTTP proxy (see RunHTTP),
// presenting auth's credentials to that proxy: Basic preemptively, and
// Digest (RFC 2617) if the upstream instead challenges a request with a 407
// -- the same handshake dialUpstreamConnect performs for CONNECT tunnels.
// Go's http.Transport has no built-in support for Digest proxy auth, so
// this drives the challenge/response itself.
type upstreamAuthTransport struct {
	inner http.RoundTripper
	auth  config.ForwardAuthConfig
}

func (t *upstreamAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var bodyBytes []byte
	if req.Body != nil && req.Body != http.NoBody {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("upstream proxy auth: read request body: %w", err)
		}
	}
	cloneWithBody := func() *http.Request {
		clone := req.Clone(req.Context())
		if bodyBytes != nil {
			clone.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
		return clone
	}

	req1 := cloneWithBody()
	creds := base64.StdEncoding.EncodeToString([]byte(t.auth.User + ":" + t.auth.Pass))
	req1.Header.Set("Proxy-Authorization", "Basic "+creds)

	resp, err := t.inner.RoundTrip(req1)
	if err != nil || resp.StatusCode != http.StatusProxyAuthRequired {
		return resp, err
	}
	ch, ok := findDigestChallenge(resp.Header.Values("Proxy-Authenticate"))
	if !ok {
		return resp, nil
	}
	resp.Body.Close()

	digestHeader, err := buildDigestAuthorization(ch, req.Method, req.URL.String(), t.auth.User, t.auth.Pass)
	if err != nil {
		return nil, fmt.Errorf("upstream proxy auth: %w", err)
	}
	req2 := cloneWithBody()
	req2.Header.Set("Proxy-Authorization", digestHeader)
	return t.inner.RoundTrip(req2)
}

// dialUpstreamConnect dials upstream (an HTTP proxy address) and issues an
// HTTP CONNECT request for targetHost, returning the tunneled connection
// once the upstream reports success. Used by handleConnect when gopr's own
// HTTP proxy is chained to an upstream one (cfg.UpstreamAddr). When auth is
// set, a Proxy-Authorization: Basic header is presented preemptively; if the
// upstream instead responds 407 with a Digest challenge, the CONNECT is
// retried once on a fresh connection with a computed Digest response.
func dialUpstreamConnect(upstream, targetHost string, auth config.ForwardAuthConfig) (net.Conn, error) {
	authHeader := ""
	if auth.User != "" {
		creds := base64.StdEncoding.EncodeToString([]byte(auth.User + ":" + auth.Pass))
		authHeader = "Basic " + creds
	}

	conn, resp, err := connectAttempt(upstream, targetHost, authHeader)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusOK {
		return conn, nil
	}
	conn.Conn.Close()

	if resp.StatusCode != http.StatusProxyAuthRequired || auth.User == "" {
		return nil, fmt.Errorf("upstream proxy %s: CONNECT %s: %s", upstream, targetHost, resp.Status)
	}
	ch, ok := findDigestChallenge(resp.Header.Values("Proxy-Authenticate"))
	if !ok {
		return nil, fmt.Errorf("upstream proxy %s: CONNECT %s: %s", upstream, targetHost, resp.Status)
	}
	digestHeader, err := buildDigestAuthorization(ch, http.MethodConnect, targetHost, auth.User, auth.Pass)
	if err != nil {
		return nil, fmt.Errorf("upstream proxy %s: %w", upstream, err)
	}

	conn, resp, err = connectAttempt(upstream, targetHost, digestHeader)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		conn.Conn.Close()
		return nil, fmt.Errorf("upstream proxy %s: CONNECT %s: %s", upstream, targetHost, resp.Status)
	}
	return conn, nil
}

// connectAttempt dials upstream and issues a single HTTP CONNECT request for
// targetHost, presenting authHeader (if non-empty) as Proxy-Authorization.
// The caller must close the returned connection unless the response is 200.
func connectAttempt(upstream, targetHost, authHeader string) (*bufferedConn, *http.Response, error) {
	conn, err := net.DialTimeout("tcp", upstream, 10*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("dial upstream proxy %s: %w", upstream, err)
	}

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: targetHost},
		Host:   targetHost,
		Header: make(http.Header),
	}
	if authHeader != "" {
		req.Header.Set("Proxy-Authorization", authHeader)
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("upstream proxy %s: write CONNECT: %w", upstream, err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("upstream proxy %s: read CONNECT response: %w", upstream, err)
	}
	resp.Body.Close()
	// The bufio.Reader used to parse the CONNECT response may have read
	// ahead into the start of the tunneled stream; preserve those bytes
	// instead of dropping them.
	return &bufferedConn{Conn: conn, r: br}, resp, nil
}

// bufferedConn wraps a net.Conn whose initial bytes have already been
// consumed into a bufio.Reader, transparently serving those buffered bytes
// first on Read.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }
