package tlsutil

import (
	"path/filepath"
	"testing"

	"github.com/pion/dtls/v3"
)

func TestServerConfigDTLS(t *testing.T) {
	dir := t.TempDir()
	certPath := writeTestCA(t, dir)

	t.Run("loads certificate", func(t *testing.T) {
		cfg, err := ServerConfigDTLS(certPath, "", "")
		if err != nil {
			t.Fatalf("ServerConfigDTLS: %v", err)
		}
		if len(cfg.Certificates) != 1 {
			t.Fatalf("Certificates = %d, want 1", len(cfg.Certificates))
		}
		if cfg.ClientAuth != 0 {
			t.Errorf("ClientAuth = %v, want zero value (no -ca= given)", cfg.ClientAuth)
		}
	})

	t.Run("with CA requires and verifies client cert", func(t *testing.T) {
		caPath := writeTestCA(t, dir)
		cfg, err := ServerConfigDTLS(certPath, "", caPath)
		if err != nil {
			t.Fatalf("ServerConfigDTLS: %v", err)
		}
		if cfg.ClientCAs == nil {
			t.Error("ClientCAs = nil, want populated pool")
		}
		if cfg.ClientAuth != dtls.RequireAndVerifyClientCert {
			t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", cfg.ClientAuth)
		}
	})

	t.Run("missing cert file is an error", func(t *testing.T) {
		if _, err := ServerConfigDTLS(filepath.Join(dir, "missing.pem"), "", ""); err == nil {
			t.Fatal("expected error for missing cert file")
		}
	})
}

func TestClientConfigDTLS(t *testing.T) {
	dir := t.TempDir()
	certPath := writeTestCA(t, dir)

	t.Run("no cert, no CA: just server name and verify flag", func(t *testing.T) {
		cfg, err := ClientConfigDTLS("", "", "", "example.com", true)
		if err != nil {
			t.Fatalf("ClientConfigDTLS: %v", err)
		}
		if cfg.ServerName != "example.com" {
			t.Errorf("ServerName = %q, want example.com", cfg.ServerName)
		}
		if cfg.InsecureSkipVerify {
			t.Error("InsecureSkipVerify = true, want false when verify=true")
		}
		if len(cfg.Certificates) != 0 {
			t.Errorf("Certificates = %d, want 0", len(cfg.Certificates))
		}
	})

	t.Run("verify=false sets InsecureSkipVerify", func(t *testing.T) {
		cfg, err := ClientConfigDTLS("", "", "", "", false)
		if err != nil {
			t.Fatalf("ClientConfigDTLS: %v", err)
		}
		if !cfg.InsecureSkipVerify {
			t.Error("InsecureSkipVerify = false, want true when verify=false")
		}
	})

	t.Run("client certificate is loaded", func(t *testing.T) {
		cfg, err := ClientConfigDTLS(certPath, "", "", "", true)
		if err != nil {
			t.Fatalf("ClientConfigDTLS: %v", err)
		}
		if len(cfg.Certificates) != 1 {
			t.Fatalf("Certificates = %d, want 1", len(cfg.Certificates))
		}
	})

	t.Run("CA pool is loaded for RootCAs", func(t *testing.T) {
		caPath := writeTestCA(t, dir)
		cfg, err := ClientConfigDTLS("", "", caPath, "", true)
		if err != nil {
			t.Fatalf("ClientConfigDTLS: %v", err)
		}
		if cfg.RootCAs == nil {
			t.Error("RootCAs = nil, want populated pool")
		}
	})
}
