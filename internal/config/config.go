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
	// are computed jointly across both endpoints (see Parse), so Target.TCP
	// always equals Listen.TCP, and likewise for UDP.
	TCP bool
	UDP bool
	// SSL reports whether this specific side is encrypted: TLS over its
	// TCP half, DTLS over its UDP half, whichever of the two are active
	// for this relay. Both share the same -cert=/-key=/-ca= (or -signca=,
	// TCP only) options.
	SSL bool
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

	KeyPath  string
	CertPath string
	CAPath   string
	// Verify reports whether the TLS certificate presented by the remote
	// side of a connection is validated. False only when -verify=0 was
	// given; true (the default) otherwise.
	Verify bool

	// SignCAPath, if set, is a PEM file containing a CA certificate *and*
	// its private key (-signca=). It switches TLS termination on the
	// listen side from a static -cert=/-key= pair to on-the-fly leaf
	// certificates, minted per hostname and signed by this CA (MITM mode).
	// Mutually exclusive with KeyPath/CertPath; only valid when Listen.SSL
	// is set and Target.SSL is not.
	SignCAPath string
	// ServerName, when set (-servername=), is the hostname used for the
	// generated leaf certificate's CN/SAN, overriding whatever SNI the
	// connecting client presents. Only meaningful together with
	// SignCAPath.
	ServerName string

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
