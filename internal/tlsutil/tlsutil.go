// Package tlsutil loads certificates/keys and builds tls.Config values for
// gopr's TLS termination (decode) and TLS origination (encode) modes.
package tlsutil

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// HasEmbeddedKey reports whether the PEM file at certPath contains a
// private key block alongside its certificate(s).
func HasEmbeddedKey(certPath string) (bool, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return false, err
	}
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return false, nil
		}
		if strings.Contains(block.Type, "PRIVATE KEY") {
			return true, nil
		}
	}
}

// loadCertificate loads a certificate (and, if present, its private key)
// from certPath, falling back to keyPath for the private key when the cert
// file has none embedded.
func loadCertificate(certPath, keyPath string) (tls.Certificate, error) {
	if keyPath == "" {
		keyPath = certPath
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load cert=%s key=%s: %w", certPath, keyPath, err)
	}
	return cert, nil
}

// loadCAPool loads a PEM-encoded CA certificate bundle used to verify a
// peer's certificate.
func loadCAPool(caPath string) (*x509.CertPool, error) {
	data, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read ca=%s: %w", caPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("ca=%s contains no usable certificates", caPath)
	}
	return pool, nil
}

// ServerConfig builds the tls.Config used to terminate TLS on the listen
// side (decode: TLS -> plaintext). When caPath is set, client certificates
// are required and verified against it (mTLS).
func ServerConfig(certPath, keyPath, caPath string) (*tls.Config, error) {
	cert, err := loadCertificate(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	if caPath != "" {
		pool, err := loadCAPool(caPath)
		if err != nil {
			return nil, err
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// mitmLeafValidity is how long each generated leaf certificate is valid
// for. Kept short (well under the ~47-day cap the CA/Browser Forum is
// phasing in industry-wide) since these are minted fresh per hostname for
// the lifetime of a single gopr process, not distributed or reused beyond
// it.
const mitmLeafValidity = 46 * 24 * time.Hour

// mitmKeyBits is the RSA key size used for generated leaf certificates.
const mitmKeyBits = 2048

// MITMSigner mints TLS server leaf certificates on demand, signed by a
// single CA loaded once at startup, and caches one certificate per
// hostname for the life of the process (regenerating an RSA key and
// signing a certificate on every connection would be needlessly
// expensive).
type MITMSigner struct {
	caCert *x509.Certificate
	caKey  crypto.Signer

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// LoadMITMSigner loads a CA certificate and its private key from a single
// PEM file at signCAPath (-signca=) and returns a signer that mints leaf
// certificates for that CA.
func LoadMITMSigner(signCAPath string) (*MITMSigner, error) {
	pair, err := tls.LoadX509KeyPair(signCAPath, signCAPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load -signca=%s (expected a PEM file containing both a CA certificate and its private key): %w", signCAPath, err)
	}
	caCert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate in -signca=%s: %w", signCAPath, err)
	}
	if !caCert.IsCA {
		return nil, fmt.Errorf("-signca=%s: certificate is not a CA (missing CA:TRUE basic constraint)", signCAPath)
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("-signca=%s: private key does not support signing", signCAPath)
	}
	return &MITMSigner{caCert: caCert, caKey: signer, cache: map[string]*tls.Certificate{}}, nil
}

// CertificateFor returns a leaf certificate for hostname, signed by the CA
// this signer was loaded from, generating and caching one on first use.
func (m *MITMSigner) CertificateFor(hostname string) (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if cert, ok := m.cache[hostname]; ok {
		return cert, nil
	}

	key, err := rsa.GenerateKey(rand.Reader, mitmKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generating leaf key for %q: %w", hostname, err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial number for %q: %w", hostname, err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: hostname},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(mitmLeafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(hostname); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{hostname}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.caCert, &key.PublicKey, m.caKey)
	if err != nil {
		return nil, fmt.Errorf("signing leaf certificate for %q: %w", hostname, err)
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{der, m.caCert.Raw},
		PrivateKey:  key,
	}
	m.cache[hostname] = cert
	return cert, nil
}

// MITMServerConfig builds the tls.Config used to terminate TLS on the
// listen side using certificates minted on demand by signer, one per
// connection hostname, instead of a single static -cert=/-key= pair
// (MITM mode, -signca=). explicitServerName (-servername=), if non-empty,
// overrides the hostname for every connection; otherwise each
// connection's own SNI is used, and a connection that presents none is
// rejected. caPath behaves exactly as in ServerConfig (optional mTLS).
func MITMServerConfig(signer *MITMSigner, explicitServerName, caPath string) (*tls.Config, error) {
	cfg := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			hostname := explicitServerName
			if hostname == "" {
				hostname = hello.ServerName
			}
			if hostname == "" {
				return nil, errors.New("gopr: no -servername= given and the client sent no SNI; cannot select a hostname for the generated certificate")
			}
			return signer.CertificateFor(hostname)
		},
	}
	if caPath != "" {
		pool, err := loadCAPool(caPath)
		if err != nil {
			return nil, err
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// ClientConfig builds the tls.Config used to originate TLS toward the
// target side (encode: plaintext -> TLS). certPath/keyPath are optional and
// present a client certificate; caPath, if set, verifies the server's
// certificate against a specific CA instead of the system pool. verify
// controls whether the server's certificate is validated at all (false when
// -verify=0 was given on the command line).
func ClientConfig(certPath, keyPath, caPath, serverName string, verify bool) (*tls.Config, error) {
	cfg := &tls.Config{ServerName: serverName, InsecureSkipVerify: !verify}
	if certPath != "" {
		cert, err := loadCertificate(certPath, keyPath)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	if caPath != "" {
		pool, err := loadCAPool(caPath)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}
