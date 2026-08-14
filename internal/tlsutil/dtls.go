// DTLS (UDP) counterparts to ServerConfig/ClientConfig in tlsutil.go. They
// share the same certificate/CA loading helpers, since -cert=/-key=/-ca=
// secure both the TCP (TLS) and UDP (DTLS) halves of a relay.
package tlsutil

import (
	"crypto/tls"

	"github.com/pion/dtls/v3"
)

// ServerConfigDTLS builds the dtls.Config used to terminate DTLS on the
// listen side (decode: DTLS -> plaintext) over UDP. Mirrors ServerConfig;
// there is no DTLS equivalent of MITMServerConfig (-M is TCP-only).
func ServerConfigDTLS(certPath, keyPath, caPath string, verifyClient bool) (*dtls.Config, error) {
	cert, err := loadCertificate(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	cfg := &dtls.Config{Certificates: []tls.Certificate{cert}}
	if caPath != "" {
		pool, err := loadCAPool(caPath)
		if err != nil {
			return nil, err
		}
		cfg.ClientCAs = pool
		if verifyClient {
			cfg.ClientAuth = dtls.RequireAndVerifyClientCert
		} else {
			cfg.ClientAuth = dtls.RequireAnyClientCert
		}
	}
	return cfg, nil
}

// ClientConfigDTLS builds the dtls.Config used to originate DTLS toward the
// target side (encode: plaintext -> DTLS) over UDP. Mirrors ClientConfig.
func ClientConfigDTLS(certPath, keyPath, caPath, serverName string, verify bool) (*dtls.Config, error) {
	cfg := &dtls.Config{ServerName: serverName, InsecureSkipVerify: !verify}
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
