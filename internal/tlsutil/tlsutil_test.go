package tlsutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestCA generates a self-signed CA certificate and private key, and
// writes them (cert block then key block) to a single PEM file, matching
// the format -signca= expects.
func writeTestCA(t *testing.T, dir string) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "gopr test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating CA certificate: %v", err)
	}

	var data []byte
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshaling CA key: %v", err)
	}
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)

	p := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadMITMSignerRejectsNonCA(t *testing.T) {
	dir := t.TempDir()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "not a ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		// IsCA deliberately left false.
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
	p := filepath.Join(dir, "notca.pem")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadMITMSigner(p); err == nil {
		t.Fatal("expected error loading a non-CA certificate as a signing CA")
	}
}

func TestMITMSignerCertificateFor(t *testing.T) {
	dir := t.TempDir()
	caPath := writeTestCA(t, dir)

	signer, err := LoadMITMSigner(caPath)
	if err != nil {
		t.Fatalf("LoadMITMSigner: %v", err)
	}

	t.Run("hostname certificate has correct CN/SAN and chains to the CA", func(t *testing.T) {
		cert, err := signer.CertificateFor("example.com")
		if err != nil {
			t.Fatalf("CertificateFor: %v", err)
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("parsing leaf: %v", err)
		}
		if leaf.Subject.CommonName != "example.com" {
			t.Errorf("CommonName = %q, want example.com", leaf.Subject.CommonName)
		}
		if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "example.com" {
			t.Errorf("DNSNames = %v, want [example.com]", leaf.DNSNames)
		}
		if len(leaf.IPAddresses) != 0 {
			t.Errorf("IPAddresses = %v, want none for a hostname", leaf.IPAddresses)
		}

		pool := x509.NewCertPool()
		pool.AddCert(signer.caCert)
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "example.com", Roots: pool}); err != nil {
			t.Errorf("leaf certificate does not verify against the signing CA: %v", err)
		}

		// NotBefore is backdated by an hour (clock-skew tolerance), so the
		// NotBefore..NotAfter span is mitmLeafValidity plus that hour.
		wantValidity := mitmLeafValidity + time.Hour
		gotValidity := leaf.NotAfter.Sub(leaf.NotBefore)
		if diff := gotValidity - wantValidity; diff < -time.Minute || diff > time.Minute {
			t.Errorf("validity period = %v, want ~%v", gotValidity, wantValidity)
		}
	})

	t.Run("IP target gets an IP SAN instead of a DNS name", func(t *testing.T) {
		cert, err := signer.CertificateFor("192.0.2.11")
		if err != nil {
			t.Fatalf("CertificateFor: %v", err)
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("parsing leaf: %v", err)
		}
		if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "192.0.2.11" {
			t.Errorf("IPAddresses = %v, want [192.0.2.11]", leaf.IPAddresses)
		}
		if len(leaf.DNSNames) != 0 {
			t.Errorf("DNSNames = %v, want none for an IP", leaf.DNSNames)
		}
	})

	t.Run("repeated calls for the same hostname are cached", func(t *testing.T) {
		c1, err := signer.CertificateFor("cached.example.com")
		if err != nil {
			t.Fatalf("CertificateFor: %v", err)
		}
		c2, err := signer.CertificateFor("cached.example.com")
		if err != nil {
			t.Fatalf("CertificateFor: %v", err)
		}
		if c1 != c2 {
			t.Errorf("CertificateFor returned different certificates for the same hostname across calls")
		}
	})

	t.Run("different hostnames get different certificates", func(t *testing.T) {
		c1, err := signer.CertificateFor("a.example.com")
		if err != nil {
			t.Fatalf("CertificateFor: %v", err)
		}
		c2, err := signer.CertificateFor("b.example.com")
		if err != nil {
			t.Fatalf("CertificateFor: %v", err)
		}
		if c1 == c2 {
			t.Errorf("CertificateFor returned the same certificate for different hostnames")
		}
	})
}

func TestMITMServerConfigGetCertificate(t *testing.T) {
	dir := t.TempDir()
	caPath := writeTestCA(t, dir)
	signer, err := LoadMITMSigner(caPath)
	if err != nil {
		t.Fatalf("LoadMITMSigner: %v", err)
	}

	t.Run("uses the client's SNI when no explicit server name is given", func(t *testing.T) {
		cfg, err := MITMServerConfig(signer, "", "")
		if err != nil {
			t.Fatalf("MITMServerConfig: %v", err)
		}
		cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "sni.example.com"})
		if err != nil {
			t.Fatalf("GetCertificate: %v", err)
		}
		leaf, _ := x509.ParseCertificate(cert.Certificate[0])
		if leaf.Subject.CommonName != "sni.example.com" {
			t.Errorf("CommonName = %q, want sni.example.com", leaf.Subject.CommonName)
		}
	})

	t.Run("explicit server name overrides SNI", func(t *testing.T) {
		cfg, err := MITMServerConfig(signer, "forced.example.com", "")
		if err != nil {
			t.Fatalf("MITMServerConfig: %v", err)
		}
		cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "sni.example.com"})
		if err != nil {
			t.Fatalf("GetCertificate: %v", err)
		}
		leaf, _ := x509.ParseCertificate(cert.Certificate[0])
		if leaf.Subject.CommonName != "forced.example.com" {
			t.Errorf("CommonName = %q, want forced.example.com", leaf.Subject.CommonName)
		}
	})

	t.Run("no explicit server name and no SNI is an error", func(t *testing.T) {
		cfg, err := MITMServerConfig(signer, "", "")
		if err != nil {
			t.Fatalf("MITMServerConfig: %v", err)
		}
		if _, err := cfg.GetCertificate(&tls.ClientHelloInfo{}); err == nil {
			t.Fatal("expected error when neither -servername= nor SNI is available")
		}
	})
}
