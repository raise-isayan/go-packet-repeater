package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"gopr/internal/config"
	"gopr/internal/logx"
)

// RunSOCKS starts a SOCKS5 proxy on cfg.Listen.Addr. Only the CONNECT
// command is supported (no BIND, no UDP ASSOCIATE), with "no
// authentication" as the sole method offered — sufficient for gopr's TCP
// relaying use case. cfg.LogLevel/cfg.Verbose select diagnostic detail and
// data dumping (-d/-v), same as forwarding mode.
//
// When cfg.UpstreamAddr is set (<target> was "<host:port>/socks"), every
// accepted CONNECT is relayed through that upstream SOCKS5 server (see
// dialUpstreamSOCKS) instead of being dialed directly.
func RunSOCKS(ctx context.Context, cfg *config.Config) error {
	log := logx.New(logx.Level(cfg.LogLevel), cfg.Verbose)
	addr := cfg.Listen.Addr
	upstream := cfg.UpstreamAddr

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	if upstream != "" {
		log.Print("socks proxy: listening on %s, forwarding via upstream socks %s", addr, upstream)
	} else {
		log.Print("socks proxy: listening on %s", addr)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go handleSOCKSConn(conn, log, upstream)
	}
}

const (
	socksVersion5 = 0x05

	socksAuthNone           = 0x00
	socksAuthNoAcceptable   = 0xFF
	socksCmdConnect         = 0x01
	socksAtypIPv4           = 0x01
	socksAtypDomain         = 0x03
	socksAtypIPv6           = 0x04
	socksReplySucceeded     = 0x00
	socksReplyGeneralFail   = 0x01
	socksReplyCmdNotSupport = 0x07
	socksReplyAtypNotSupp   = 0x08
)

func handleSOCKSConn(conn net.Conn, log *logx.Logger, upstream string) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	label := fmt.Sprintf("socks %s", conn.RemoteAddr())
	log.Warn("%s: accepted", label)
	start := time.Now()

	if err := socksHandshake(conn); err != nil {
		log.Error("socks: %s: handshake: %v", conn.RemoteAddr(), err)
		return
	}

	target, err := socksReadRequest(conn)
	if err != nil {
		log.Error("socks: %s: request: %v", conn.RemoteAddr(), err)
		return
	}

	var dst net.Conn
	if upstream != "" {
		dst, err = dialUpstreamSOCKS(upstream, target)
	} else {
		dst, err = net.DialTimeout("tcp", target, 10*time.Second)
	}
	if err != nil {
		log.Error("socks: %s: dial %s: %v", conn.RemoteAddr(), target, err)
		socksWriteReply(conn, socksReplyGeneralFail)
		return
	}
	defer dst.Close()

	if err := socksWriteReply(conn, socksReplySucceeded); err != nil {
		return
	}
	log.Info("%s: connected to %s", label, target)

	conn.SetDeadline(time.Time{})
	sent, recv := pipeSOCKS(log, label, conn, dst)
	if log.InfoEnabled() {
		log.Info("%s: closed (sent=%d recv=%d duration=%s)", label, sent, recv, time.Since(start).Round(time.Millisecond))
	} else {
		log.Warn("%s: closed", label)
	}
}

func socksHandshake(conn net.Conn) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return err
	}
	if hdr[0] != socksVersion5 {
		return fmt.Errorf("unsupported SOCKS version %d", hdr[0])
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	for _, m := range methods {
		if m == socksAuthNone {
			_, err := conn.Write([]byte{socksVersion5, socksAuthNone})
			return err
		}
	}
	conn.Write([]byte{socksVersion5, socksAuthNoAcceptable})
	return errors.New("no acceptable authentication method")
}

func socksReadRequest(conn net.Conn) (string, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return "", err
	}
	if hdr[0] != socksVersion5 {
		return "", fmt.Errorf("unsupported SOCKS version %d", hdr[0])
	}
	if hdr[1] != socksCmdConnect {
		socksWriteReply(conn, socksReplyCmdNotSupport)
		return "", fmt.Errorf("unsupported command %d (only CONNECT is supported)", hdr[1])
	}

	var host string
	switch hdr[3] {
	case socksAtypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case socksAtypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case socksAtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", err
		}
		b := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		socksWriteReply(conn, socksReplyAtypNotSupp)
		return "", fmt.Errorf("unsupported address type %d", hdr[3])
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBuf)

	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func socksWriteReply(conn net.Conn, replyCode byte) error {
	// BND.ADDR/BND.PORT are not meaningful for this proxy; report the
	// wildcard address as most minimal SOCKS5 servers do.
	reply := []byte{socksVersion5, replyCode, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0}
	_, err := conn.Write(reply)
	return err
}

// pipeSOCKS relays data bidirectionally between the client (a) and target
// (b) connections, honoring log's -ddd/-v instrumentation. sent is bytes
// a->b, recv is bytes b->a.
func pipeSOCKS(log *logx.Logger, label string, a, b net.Conn) (sent, recv int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		recv, _ = logx.Copy(log, label, false, a, b)
		if hc, ok := a.(halfCloser); ok {
			hc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		sent, _ = logx.Copy(log, label, true, b, a)
		if hc, ok := b.(halfCloser); ok {
			hc.CloseWrite()
		}
	}()
	wg.Wait()
	return sent, recv
}

type halfCloser interface {
	CloseWrite() error
}

// dialUpstreamSOCKS dials upstream (a SOCKS5 server address) and issues a
// CONNECT request for target ("host:port"), returning the established
// connection once the upstream reports success. Used by handleSOCKSConn
// when gopr's own SOCKS proxy is chained to an upstream one
// (cfg.UpstreamAddr). Only "no authentication" is offered, matching
// RunSOCKS's own server-side support.
func dialUpstreamSOCKS(upstream, target string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", upstream, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial upstream socks %s: %w", upstream, err)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{})

	if _, err := conn.Write([]byte{socksVersion5, 1, socksAuthNone}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("upstream socks %s: write greeting: %w", upstream, err)
	}
	methodResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, methodResp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("upstream socks %s: read greeting response: %w", upstream, err)
	}
	if methodResp[0] != socksVersion5 || methodResp[1] != socksAuthNone {
		conn.Close()
		return nil, fmt.Errorf("upstream socks %s: no acceptable authentication method (server chose %d)", upstream, methodResp[1])
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("upstream socks %s: invalid target %q: %w", upstream, target, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("upstream socks %s: invalid target port %q: %w", upstream, portStr, err)
	}
	req := make([]byte, 0, 7+len(host))
	req = append(req, socksVersion5, socksCmdConnect, 0x00)
	switch ip := net.ParseIP(host); {
	case ip != nil && ip.To4() != nil:
		req = append(req, socksAtypIPv4)
		req = append(req, ip.To4()...)
	case ip != nil:
		req = append(req, socksAtypIPv6)
		req = append(req, ip.To16()...)
	case len(host) > 255:
		conn.Close()
		return nil, fmt.Errorf("upstream socks %s: target host too long: %q", upstream, host)
	default:
		req = append(req, socksAtypDomain, byte(len(host)))
		req = append(req, host...)
	}
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(port))
	req = append(req, portBuf...)
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("upstream socks %s: write CONNECT request: %w", upstream, err)
	}

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("upstream socks %s: read CONNECT reply: %w", upstream, err)
	}
	if hdr[0] != socksVersion5 {
		conn.Close()
		return nil, fmt.Errorf("upstream socks %s: unexpected SOCKS version %d in CONNECT reply", upstream, hdr[0])
	}
	if hdr[1] != socksReplySucceeded {
		conn.Close()
		return nil, fmt.Errorf("upstream socks %s: CONNECT %s failed: reply code %d", upstream, target, hdr[1])
	}

	// BND.ADDR/BND.PORT follow and must be consumed even though gopr has
	// no use for them, so the connection is left at the start of the
	// relayed byte stream.
	var addrLen int
	switch hdr[3] {
	case socksAtypIPv4:
		addrLen = 4
	case socksAtypIPv6:
		addrLen = 16
	case socksAtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			conn.Close()
			return nil, fmt.Errorf("upstream socks %s: read CONNECT reply address: %w", upstream, err)
		}
		addrLen = int(lenBuf[0])
	default:
		conn.Close()
		return nil, fmt.Errorf("upstream socks %s: unknown address type %d in CONNECT reply", upstream, hdr[3])
	}
	if _, err := io.CopyN(io.Discard, conn, int64(addrLen+2)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("upstream socks %s: read CONNECT reply address: %w", upstream, err)
	}

	return conn, nil
}
