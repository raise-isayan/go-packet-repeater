// Package config parses gopr's command-line arguments into a Config value,
// following the specification in SKILL.md.
package config

// Mode selects what gopr does with the parsed arguments.
type Mode int

const (
	// ModeForward relays TCP and/or UDP traffic from Listen to Target.
	ModeForward Mode = iota
	// ModeHTTPProxy runs an HTTP proxy on Listen.
	ModeHTTPProxy
	// ModeSOCKSProxy runs a SOCKS proxy on Listen.
	ModeSOCKSProxy
	// ModeVersion prints the version and exits; no other fields are populated.
	ModeVersion
	// ModeHelp prints usage information and exits; no other fields are populated.
	ModeHelp
)

// Endpoint is one side (target or listen) of a forwarding relay: a network
// address plus which protocols and TLS behavior apply to it.
type Endpoint struct {
	// Addr is the normalized address, ready for net.Dial / net.Listen
	// (e.g. "192.168.0.2:7777", "[2001:db8::2]:7777", "0.0.0.0:8888").
	Addr string
	// TCP and UDP report which protocols this relay operates over. These
	// are declared on the listen side only (see Parse) and mirrored onto
	// both endpoints, so Target.TCP always equals Listen.TCP, and likewise
	// for UDP.
	TCP bool
	UDP bool
	// SSL reports whether this specific side is encrypted: TLS over its
	// TCP half, DTLS over its UDP half, whichever of the two are active
	// for this relay. Both share the same -cert=/-key=/-ca= (or -signca=,
	// TCP only) options.
	SSL bool
}

// ClientTLSConfig is the -Q <SSL> block: how gopr behaves as a TLS/DTLS
// client originating encryption toward Target.
type ClientTLSConfig struct {
	// KeyPath/CertPath, if set, present a client certificate to Target.
	// Both are optional -- a plain TLS/DTLS client needs neither.
	KeyPath, CertPath string
	// CAPath, if set, verifies Target's certificate against this CA
	// instead of the system root pool.
	CAPath string
	// Verify reports whether Target's certificate is validated at all.
	// False only when -verify=0 was given under -Q; true (the default)
	// otherwise.
	Verify bool
}

// ServerTLSConfig is the -Z <SSL> block: a static certificate for TLS/DTLS
// termination on Listen.
type ServerTLSConfig struct {
	// KeyPath/CertPath are this side's own certificate, required whenever
	// Listen.SSL is set (unless MITM is used instead).
	KeyPath, CertPath string
	// CAPath, if set, requests and verifies a client certificate from the
	// connecting peer (mTLS).
	CAPath string
	// VerifyClient reports whether a client certificate presented under
	// CAPath is validated against it. False only when -verify=0 was given
	// under -Z; true (the default) otherwise. Has no effect when CAPath is
	// empty (no client certificate is requested at all).
	VerifyClient bool
}

// MITMConfig is the -M <MITM> block: mints a per-connection leaf
// certificate for TLS termination on Listen instead of a static
// ServerTLSConfig certificate.
type MITMConfig struct {
	// SignCAPath is a PEM file containing a CA certificate *and* its
	// private key (-signca=), used to sign generated leaf certificates.
	SignCAPath string
	// ServerName, when set (-servername=), is the hostname used for the
	// generated leaf certificate's CN/SAN, overriding whatever SNI the
	// connecting client presents.
	ServerName string
	// CAPath, if set, requests and verifies a client certificate from the
	// connecting peer (mTLS), exactly as ServerTLSConfig.CAPath.
	CAPath string
	// VerifyClient behaves exactly as ServerTLSConfig.VerifyClient.
	VerifyClient bool
}

// Config is the fully parsed and validated representation of a gopr
// command line.
type Config struct {
	Mode Mode

	// Target and Listen are populated when Mode == ModeForward.
	Target Endpoint
	// Listen is always populated: it is the relay's listen address in
	// ModeForward, and the proxy's listen address in ModeHTTPProxy /
	// ModeSOCKSProxy.
	Listen Endpoint

	// UpstreamAddr, when non-empty, chains this proxy to an upstream
	// proxy/SOCKS server of the same kind instead of dialing the client's
	// requested destination directly: an HTTP CONNECT (or plain request)
	// is relayed through it in ModeHTTPProxy, and a SOCKS5 CONNECT in
	// ModeSOCKSProxy. Only set when Mode is ModeHTTPProxy or
	// ModeSOCKSProxy and <target> was given as "<host:port>/proxy" or
	// "<host:port>/socks"; empty for the bare "proxy"/"socks" keyword
	// form, which dials directly as before.
	UpstreamAddr string

	// ClientTLS holds the -Q <SSL> block: gopr's own TLS/DTLS behavior when
	// it acts as the client originating encryption toward Target (only
	// meaningful when Target.SSL is set).
	ClientTLS ClientTLSConfig
	// ServerTLS holds the -Z <SSL> block: a static certificate for TLS/DTLS
	// termination on Listen (only meaningful when Listen.SSL is set).
	// Mutually exclusive with MITM.
	ServerTLS ServerTLSConfig
	// MITM holds the -M <MITM> block: an alternative to ServerTLS that
	// mints a per-connection leaf certificate for TLS termination on
	// Listen instead of using a static certificate. Mutually exclusive
	// with ServerTLS; TCP only (no DTLS/UDP support).
	MITM MITMConfig

	// LogLevel selects how much diagnostic detail gopr prints, following
	// socat's -d stacking convention: 0 (default, no -d) is errors only,
	// -d/-dd/-ddd raise it to 1/2/3 (see internal/logx for what each tier
	// adds). Always in [0,3].
	LogLevel int
	// Verbose reports whether -v was given: dump the actual content
	// relayed between target and listen to stderr. Independent of
	// LogLevel, mirroring socat's -v.
	Verbose bool
}
