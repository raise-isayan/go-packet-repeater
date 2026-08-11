package relay

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"gopr/internal/config"
	"gopr/internal/logx"
)

// serveTCP accepts TCP connections on cfg.Listen, dials cfg.Target for
// each one, and relays data between them. TLS termination (Listen.SSL) and
// TLS origination (Target.SSL) are applied independently of each other.
func serveTCP(ctx context.Context, cfg *config.Config, log *logx.Logger) error {
	var ln net.Listener
	var err error
	if cfg.Listen.SSL {
		tlsCfg, cfgErr := serverTLSConfig(cfg)
		if cfgErr != nil {
			return cfgErr
		}
		ln, err = tls.Listen("tcp", cfg.Listen.Addr, tlsCfg)
	} else {
		ln, err = net.Listen("tcp", cfg.Listen.Addr)
	}
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	log.Print("tcp: listening on %s -> %s", cfg.Listen.Addr, cfg.Target.Addr)
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
		go handleTCPConn(conn, cfg, log)
	}
}

func handleTCPConn(src net.Conn, cfg *config.Config, log *logx.Logger) {
	defer src.Close()

	label := fmt.Sprintf("tcp %s", src.RemoteAddr())
	log.Warn("%s: accepted", label)
	start := time.Now()

	var dst net.Conn
	var err error
	if cfg.Target.SSL {
		tlsCfg, cfgErr := clientTLSConfig(cfg)
		if cfgErr != nil {
			log.Error("tcp: %s: %v", src.RemoteAddr(), cfgErr)
			return
		}
		dst, err = tls.Dial("tcp", cfg.Target.Addr, tlsCfg)
	} else {
		dst, err = net.Dial("tcp", cfg.Target.Addr)
	}
	if err != nil {
		log.Error("tcp: %s: dial %s: %v", src.RemoteAddr(), cfg.Target.Addr, err)
		return
	}
	defer dst.Close()

	log.Info("%s: connected to %s", label, cfg.Target.Addr)
	if tlsConn, ok := dst.(*tls.Conn); ok && log.InfoEnabled() {
		state := tlsConn.ConnectionState()
		log.Info("%s: tls handshake with target: version=%x cipher=%s", label, state.Version, tls.CipherSuiteName(state.CipherSuite))
	}

	sent, recv := pipeConn(log, label, src, dst)
	if log.InfoEnabled() {
		log.Info("%s: closed (sent=%d recv=%d duration=%s)", label, sent, recv, time.Since(start).Round(time.Millisecond))
	} else {
		log.Warn("%s: closed", label)
	}
}

// halfCloser is implemented by net.Conn types (net.TCPConn, tls.Conn) that
// support shutting down just the write half of the connection.
type halfCloser interface {
	CloseWrite() error
}

// pipeConn relays data bidirectionally between two net.Conn values until
// both directions are drained, honoring log's -ddd (per-chunk trace) and -v
// (data dump) instrumentation. It has no other protocol-specific logic, so
// it is shared by the TCP relay (tcp.go) and the DTLS-over-UDP relay
// (udp.go). a is treated as the client side and b as the target side for
// direction reporting; sent is bytes a->b, recv is bytes b->a.
func pipeConn(log *logx.Logger, label string, a, b net.Conn) (sent, recv int64) {
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
