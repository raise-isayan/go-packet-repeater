// Package relay implements gopr's forwarding mode: it listens on one
// address and pipes TCP/UDP traffic to a target address, optionally
// terminating or originating TLS along the way.
package relay

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"sync"

	"github.com/pion/dtls/v3"

	"gopr/internal/config"
	"gopr/internal/logx"
	"gopr/internal/tlsutil"
)

// Run starts whichever listeners cfg.Target/cfg.Listen require (TCP, UDP,
// or both) and blocks until ctx is cancelled or a listener fails fatally.
func Run(ctx context.Context, cfg *config.Config) error {
	log := logx.New(logx.Level(cfg.LogLevel), cfg.Verbose)

	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	if cfg.Listen.TCP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := serveTCP(ctx, cfg, log); err != nil {
				errCh <- fmt.Errorf("tcp: %w", err)
			}
		}()
	}
	if cfg.Listen.UDP {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := serveUDP(ctx, cfg, log); err != nil {
				errCh <- fmt.Errorf("udp: %w", err)
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case err := <-errCh:
		return err
	case <-done:
		return nil
	case <-ctx.Done():
		<-done
		return nil
	}
}

func serverName(addr string) string {
	host, _, err := splitHostPort(addr)
	if err != nil {
		return ""
	}
	return host
}

func splitHostPort(addr string) (host, port string, err error) {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return addr, "", fmt.Errorf("no port in address %q", addr)
	}
	host = strings.Trim(addr[:i], "[]")
	return host, addr[i+1:], nil
}

func clientTLSConfig(cfg *config.Config) (*tls.Config, error) {
	return tlsutil.ClientConfig(cfg.CertPath, cfg.KeyPath, cfg.CAPath, serverName(cfg.Target.Addr), cfg.Verify)
}

func serverTLSConfig(cfg *config.Config) (*tls.Config, error) {
	if cfg.SignCAPath != "" {
		signer, err := tlsutil.LoadMITMSigner(cfg.SignCAPath)
		if err != nil {
			return nil, err
		}
		return tlsutil.MITMServerConfig(signer, cfg.ServerName, cfg.CAPath)
	}
	return tlsutil.ServerConfig(cfg.CertPath, cfg.KeyPath, cfg.CAPath)
}

func clientDTLSConfig(cfg *config.Config) (*dtls.Config, error) {
	return tlsutil.ClientConfigDTLS(cfg.CertPath, cfg.KeyPath, cfg.CAPath, serverName(cfg.Target.Addr), cfg.Verify)
}

func serverDTLSConfig(cfg *config.Config) (*dtls.Config, error) {
	return tlsutil.ServerConfigDTLS(cfg.CertPath, cfg.KeyPath, cfg.CAPath)
}
