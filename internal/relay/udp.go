package relay

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v3"

	"gopr/internal/config"
	"gopr/internal/logx"
)

// udpSessionIdleTimeout is how long a client's UDP "session" (the mapping
// from client address to the outbound connection toward Target) is kept
// alive without traffic before it is torn down.
const udpSessionIdleTimeout = 2 * time.Minute

const udpBufferSize = 64 * 1024

// udpSession tracks the connection used to relay one client's traffic to
// Target, and back again. sent/recv are updated from multiple goroutines
// (the main receive loop and relayUDPReplies), hence atomic.
type udpSession struct {
	conn       *net.UDPConn // connected socket toward Target
	last       time.Time
	sent, recv atomic.Int64
}

// serveUDP listens for UDP packets on cfg.Listen and forwards each client's
// traffic to cfg.Target over its own outbound UDP socket, relaying replies
// back to the originating client address. When cfg.Listen.SSL is set, it
// delegates to serveUDPDTLS instead: DTLS is connection-oriented (a
// handshake per client, demultiplexed by pion), which doesn't fit this
// function's plaintext client-address session map.
func serveUDP(ctx context.Context, cfg *config.Config, log *logx.Logger) error {
	if cfg.Listen.SSL {
		return serveUDPDTLS(ctx, cfg, log)
	}

	listenAddr, err := net.ResolveUDPAddr("udp", cfg.Listen.Addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	log.Print("udp: listening on %s -> %s", cfg.Listen.Addr, cfg.Target.Addr)

	var mu sync.Mutex
	sessions := make(map[string]*udpSession)

	stop := make(chan struct{})
	defer close(stop)
	go reapUDPSessions(stop, &mu, sessions, log)

	buf := make([]byte, udpBufferSize)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}

		// key doubles as the diagnostic label ("udp <clientAddr>"); no
		// eager formatting happens here so the hot path stays allocation-
		// free when no -d/-v is active.
		key := clientAddr.String()
		mu.Lock()
		sess, ok := sessions[key]
		if !ok {
			targetConn, err := net.Dial("udp", cfg.Target.Addr)
			if err != nil {
				mu.Unlock()
				log.Error("udp: %s: dial %s: %v", key, cfg.Target.Addr, err)
				continue
			}
			sess = &udpSession{conn: targetConn.(*net.UDPConn), last: time.Now()}
			sessions[key] = sess
			log.Warn("udp %s: session created (-> %s)", key, cfg.Target.Addr)
			go relayUDPReplies(conn, sess, clientAddr, &mu, sessions, key, log)
		}
		sess.last = time.Now()
		mu.Unlock()

		if log.Verbose() {
			log.Data("udp "+key, true, buf[:n])
		}
		log.Debug("udp %s: -> %d bytes", key, n)

		if _, err := sess.conn.Write(buf[:n]); err != nil {
			log.Error("udp: %s: write to target: %v", key, err)
			continue
		}
		sess.sent.Add(int64(n))
	}
}

// relayUDPReplies copies packets arriving from Target back to the client
// that owns sess, until the target connection is closed (idle reap) or
// errors out.
func relayUDPReplies(listenConn *net.UDPConn, sess *udpSession, clientAddr *net.UDPAddr, mu *sync.Mutex, sessions map[string]*udpSession, key string, log *logx.Logger) {
	buf := make([]byte, udpBufferSize)
	for {
		n, err := sess.conn.Read(buf)
		if err != nil {
			mu.Lock()
			if sessions[key] == sess {
				delete(sessions, key)
			}
			mu.Unlock()
			sess.conn.Close()
			if log.InfoEnabled() {
				log.Info("udp %s: session closed (sent=%d recv=%d)", key, sess.sent.Load(), sess.recv.Load())
			} else {
				log.Warn("udp %s: session closed", key)
			}
			return
		}

		if log.Verbose() {
			log.Data("udp "+key, false, buf[:n])
		}
		log.Debug("udp %s: <- %d bytes", key, n)
		sess.recv.Add(int64(n))

		mu.Lock()
		sess.last = time.Now()
		mu.Unlock()
		if _, err := listenConn.WriteToUDP(buf[:n], clientAddr); err != nil {
			return
		}
	}
}

func reapUDPSessions(stop <-chan struct{}, mu *sync.Mutex, sessions map[string]*udpSession, log *logx.Logger) {
	ticker := time.NewTicker(udpSessionIdleTimeout / 2)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			mu.Lock()
			now := time.Now()
			for key, sess := range sessions {
				if now.Sub(sess.last) > udpSessionIdleTimeout {
					sess.conn.Close()
					delete(sessions, key)
					log.Warn("udp %s: session reaped (idle %s)", key, udpSessionIdleTimeout)
				}
			}
			mu.Unlock()
		}
	}
}

// serveUDPDTLS listens for DTLS connections on cfg.Listen (decode: DTLS ->
// plaintext) and forwards each one to cfg.Target, optionally DTLS-wrapped
// itself (encode: plaintext -> DTLS) when cfg.Target.SSL is set. Unlike
// serveUDP, no client-address session map is needed: pion's DTLS listener
// already demultiplexes clients by source address during the handshake and
// hands back one net.Conn per client, mirroring serveTCP/handleTCPConn.
func serveUDPDTLS(ctx context.Context, cfg *config.Config, log *logx.Logger) error {
	dtlsCfg, err := serverDTLSConfig(cfg)
	if err != nil {
		return err
	}
	listenAddr, err := net.ResolveUDPAddr("udp", cfg.Listen.Addr)
	if err != nil {
		return err
	}
	ln, err := dtls.Listen("udp", listenAddr, dtlsCfg)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	log.Print("udp+dtls: listening on %s -> %s", cfg.Listen.Addr, cfg.Target.Addr)
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
		go handleUDPDTLSConn(conn, cfg, log)
	}
}

func handleUDPDTLSConn(src net.Conn, cfg *config.Config, log *logx.Logger) {
	defer src.Close()

	label := fmt.Sprintf("udp+dtls %s", src.RemoteAddr())
	log.Warn("%s: accepted", label)
	start := time.Now()

	var dst net.Conn
	var err error
	if cfg.Target.SSL {
		dtlsCfg, cfgErr := clientDTLSConfig(cfg)
		if cfgErr != nil {
			log.Error("udp+dtls: %s: %v", src.RemoteAddr(), cfgErr)
			return
		}
		targetAddr, resolveErr := net.ResolveUDPAddr("udp", cfg.Target.Addr)
		if resolveErr != nil {
			log.Error("udp+dtls: %s: resolve target %s: %v", src.RemoteAddr(), cfg.Target.Addr, resolveErr)
			return
		}
		dst, err = dtls.Dial("udp", targetAddr, dtlsCfg)
	} else {
		dst, err = net.Dial("udp", cfg.Target.Addr)
	}
	if err != nil {
		log.Error("udp+dtls: %s: dial %s: %v", src.RemoteAddr(), cfg.Target.Addr, err)
		return
	}
	defer dst.Close()

	log.Info("%s: connected to %s", label, cfg.Target.Addr)

	sent, recv := pipeConn(log, label, src, dst)
	if log.InfoEnabled() {
		log.Info("%s: closed (sent=%d recv=%d duration=%s)", label, sent, recv, time.Since(start).Round(time.Millisecond))
	} else {
		log.Warn("%s: closed", label)
	}
}
