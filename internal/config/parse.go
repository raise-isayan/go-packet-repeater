package config

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"gopr/internal/tlsutil"
)

// keywordOrder fixes the required TCP -> UDP -> SSL ordering for suffixes
// attached to a target/listen token (e.g. "8888/TCP/UDP/SSL").
var keywordOrder = map[string]int{
	"TCP": 0,
	"UDP": 1,
	"SSL": 2,
}

// Usage is gopr's command-line synopsis, printed by -help and appended to
// the error returned when the positional argument count is wrong.
const Usage = `gopr [option] <target> <listen>

[option]
  [-key=<path>]           ; key file
  [-cert=<path>]          ; cert file
  [-ca=<path>]            ; ca file
  [-verify=<value>]       ; verify=0 Do not verify the TLS certificate.
  [-signca=<path>]        ; CA (cert + private key) used to mint a leaf
                          ; certificate per connection for TLS termination
                          ; (MITM). Mutually exclusive with -cert=/-key=.
  [-servername=<value>]   ; hostname for the generated certificate;
                          ; overrides the client's SNI. Requires -signca=.
  [-d | -dd | -ddd]       ; debug output; each additional d prints one more,
                          ; less severe tier of diagnostics (socat-style):
                          ; -d = connection/session lifecycle, -dd = adds
                          ; per-connection detail (dial/handshake results,
                          ; byte counts), -ddd = adds per-chunk/per-packet
                          ; trace. Default (no -d) is errors only.
  [-v]                    ; dump the data relayed between target and listen
                          ; to stderr. Independent of -d. May reveal
                          ; sensitive content -- use with care.
  [-help]                 ; show help
  [-version]              ; show version`

// ParseAll builds one Config per "--"-separated group of arguments in args.
// "gopr A -- B" behaves like running "gopr A" and "gopr B" concurrently as
// a single process. With no "--" present, it behaves exactly like Parse and
// returns a single Config (which may be ModeHelp/ModeVersion).
//
// Parsing is all-or-nothing: every group must be individually valid, and
// -help/-version may only appear when args contains no "--" at all (they
// don't make sense mixed with other targets). If any group is invalid, or
// -help/-version is combined with "--", ParseAll returns a single combined
// error and no Configs, so a multi-target invocation never partially starts.
func ParseAll(args []string) ([]*Config, error) {
	groups := splitArgGroups(args)
	if len(groups) == 1 {
		cfg, err := Parse(groups[0])
		if err != nil {
			return nil, err
		}
		return []*Config{cfg}, nil
	}

	cfgs := make([]*Config, 0, len(groups))
	var errs []error
	for i, g := range groups {
		cfg, err := Parse(g)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("argument group %d (%q): %w", i+1, strings.Join(g, " "), err))
		case cfg.Mode == ModeHelp || cfg.Mode == ModeVersion:
			errs = append(errs, fmt.Errorf("argument group %d (%q): -help/-version cannot be combined with -- to specify multiple targets", i+1, strings.Join(g, " ")))
		default:
			cfgs = append(cfgs, cfg)
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return cfgs, nil
}

// splitArgGroups splits args into groups separated by the literal token
// "--". A single group (no "--" present) is returned as-is.
func splitArgGroups(args []string) [][]string {
	groups := [][]string{nil}
	for _, a := range args {
		if a == "--" {
			groups = append(groups, nil)
			continue
		}
		last := len(groups) - 1
		groups[last] = append(groups[last], a)
	}
	return groups
}

// Parse builds a Config from command-line arguments (os.Args[1:]).
func Parse(args []string) (*Config, error) {
	opts, rest, err := extractOptions(args)
	if err != nil {
		return nil, err
	}
	// -help and -version take precedence over every other option and need
	// no positional arguments; -help wins if both are given.
	if opts.help {
		return &Config{Mode: ModeHelp}, nil
	}
	if opts.version {
		return &Config{Mode: ModeVersion}, nil
	}
	if len(rest) != 2 {
		return nil, fmt.Errorf("expected exactly 2 positional arguments (<target> <listen>), got %d\n%s", len(rest), Usage)
	}
	targetTok, listenTok := rest[0], rest[1]

	if mode, ok := proxyMode(targetTok); ok {
		if opts.keyPath != "" || opts.certPath != "" || opts.caPath != "" || opts.signCAPath != "" || opts.serverName != "" {
			return nil, errors.New("proxy/socks mode cannot be combined with -key=/-cert=/-ca=/-signca=/-servername=")
		}
		if strings.Contains(listenTok, "/") {
			return nil, fmt.Errorf("proxy/socks mode cannot be combined with protocol suffixes: %q", listenTok)
		}
		addr, err := normalizeAddr(listenTok, false)
		if err != nil {
			return nil, err
		}
		return &Config{
			Mode:     mode,
			Listen:   Endpoint{Addr: addr, TCP: true},
			LogLevel: opts.logLevel,
			Verbose:  opts.verbose,
		}, nil
	}

	target, err := parseEndpoint(targetTok, true)
	if err != nil {
		return nil, err
	}
	listen, err := parseEndpoint(listenTok, false)
	if err != nil {
		return nil, err
	}

	// TCP/UDP are properties of the relay as a whole: whichever side
	// declares them wins. Default to TCP-only when neither side says
	// anything.
	tcp := target.tcp || listen.tcp
	udp := target.udp || listen.udp
	if !tcp && !udp {
		tcp = true
	}
	target.ep.TCP, listen.ep.TCP = tcp, tcp
	target.ep.UDP, listen.ep.UDP = udp, udp

	// SSL applies to whichever of TCP/UDP are active for a relay: TLS on
	// the TCP half, DTLS on the UDP half, sharing the same cert options.
	sslListenTCP := tcp && listen.ep.SSL
	sslListenUDP := udp && listen.ep.SSL
	sslTargetTCP := tcp && target.ep.SSL
	sslTargetUDP := udp && target.ep.SSL
	sslListen := sslListenTCP || sslListenUDP
	sslTarget := sslTargetTCP || sslTargetUDP
	if err := validateCerts(opts, sslListen, sslListenUDP, sslTarget); err != nil {
		return nil, err
	}

	return &Config{
		Mode:       ModeForward,
		Target:     target.ep,
		Listen:     listen.ep,
		KeyPath:    opts.keyPath,
		CertPath:   opts.certPath,
		CAPath:     opts.caPath,
		Verify:     opts.verify,
		SignCAPath: opts.signCAPath,
		ServerName: opts.serverName,
		LogLevel:   opts.logLevel,
		Verbose:    opts.verbose,
	}, nil
}

// options holds every -flag= gopr accepts, before the target/listen
// positional arguments have been parsed.
type options struct {
	keyPath, certPath, caPath string
	signCAPath, serverName    string
	verify                    bool
	help, version             bool
	// logLevel is the highest of any -d/-dd/-ddd given (0 if none), per
	// socat's stacking convention; see Config.LogLevel.
	logLevel int
	// verbose is set by -v; see Config.Verbose.
	verbose bool
}

// logLevelTokens maps the literal -d/-dd/-ddd tokens to the logx.Level they
// select. Stacking is by whichever token gives the highest level (so
// "-d -ddd" and "-ddd -d" both end up at level 3) rather than summing, to
// keep repeated/combined -d tokens forgiving instead of an error.
var logLevelTokens = map[string]int{
	"-d":   1,
	"-dd":  2,
	"-ddd": 3,
}

// extractOptions consumes leading -key=/-cert=/-ca=/-verify=/-signca=/
// -servername=/-d/-dd/-ddd/-v/-help/-version tokens (any order, each at
// most once except -d/-dd/-ddd/-v which may repeat) and returns the
// remaining positional arguments. verify defaults to true; it is false only
// when -verify=0 was given.
func extractOptions(args []string) (options, []string, error) {
	opts := options{verify: true}
	i := 0
	for ; i < len(args); i++ {
		tok := args[i]
		switch {
		case tok == "-help":
			opts.help = true
		case tok == "-version":
			opts.version = true
		case tok == "-v":
			opts.verbose = true
		case logLevelTokens[tok] != 0:
			if lvl := logLevelTokens[tok]; lvl > opts.logLevel {
				opts.logLevel = lvl
			}
		case strings.HasPrefix(tok, "-key="):
			if opts.keyPath != "" {
				return options{}, nil, errors.New("-key= specified more than once")
			}
			opts.keyPath = strings.TrimPrefix(tok, "-key=")
		case strings.HasPrefix(tok, "-cert="):
			if opts.certPath != "" {
				return options{}, nil, errors.New("-cert= specified more than once")
			}
			opts.certPath = strings.TrimPrefix(tok, "-cert=")
		case strings.HasPrefix(tok, "-ca="):
			if opts.caPath != "" {
				return options{}, nil, errors.New("-ca= specified more than once")
			}
			opts.caPath = strings.TrimPrefix(tok, "-ca=")
		case strings.HasPrefix(tok, "-signca="):
			if opts.signCAPath != "" {
				return options{}, nil, errors.New("-signca= specified more than once")
			}
			opts.signCAPath = strings.TrimPrefix(tok, "-signca=")
		case strings.HasPrefix(tok, "-servername="):
			if opts.serverName != "" {
				return options{}, nil, errors.New("-servername= specified more than once")
			}
			opts.serverName = strings.TrimPrefix(tok, "-servername=")
		case strings.HasPrefix(tok, "-verify="):
			opts.verify = strings.TrimPrefix(tok, "-verify=") != "0"
		default:
			return opts, args[i:], nil
		}
	}
	return opts, args[i:], nil
}

// proxyMode reports whether tok is an exact, case-consistent match for the
// literal "proxy" or "socks" keyword, per SKILL.md's "ポート有無で判定する
// キーワード方式". A token like "Proxy" (mixed case) or "proxy:7777"
// (carries a port) does not match, and is left to fall through to normal
// hostname parsing.
func proxyMode(tok string) (Mode, bool) {
	switch {
	case matchKeyword(tok, "proxy"):
		return ModeHTTPProxy, true
	case matchKeyword(tok, "socks"):
		return ModeSOCKSProxy, true
	default:
		return 0, false
	}
}

// matchKeyword reports whether tok equals word, either entirely uppercase
// or entirely lowercase. Mixed-case tokens (e.g. "Tcp") never match.
func matchKeyword(tok, word string) bool {
	return tok == strings.ToUpper(word) || tok == strings.ToLower(word)
}

// parsedEndpoint carries the boolean TCP/UDP suffix presence separately
// from the final Endpoint, since the final TCP/UDP flags are only decided
// once both target and listen tokens have been parsed.
type parsedEndpoint struct {
	ep       Endpoint
	tcp, udp bool
}

// parseEndpoint splits tok into its address and "/TCP" "/UDP" "/SSL"
// suffixes, and validates each part.
func parseEndpoint(tok string, isTarget bool) (parsedEndpoint, error) {
	addrTok := tok
	var suffixToks []string
	if idx := strings.IndexByte(tok, '/'); idx >= 0 {
		addrTok = tok[:idx]
		suffixToks = strings.Split(tok[idx+1:], "/")
	}

	addr, err := normalizeAddr(addrTok, isTarget)
	if err != nil {
		return parsedEndpoint{}, err
	}

	pe := parsedEndpoint{ep: Endpoint{Addr: addr}}
	last := -1
	seen := map[string]bool{}
	for _, s := range suffixToks {
		if s == "" {
			return parsedEndpoint{}, fmt.Errorf("empty protocol suffix in %q", tok)
		}
		upper := strings.ToUpper(s)
		if s != upper && s != strings.ToLower(s) {
			return parsedEndpoint{}, fmt.Errorf("protocol keyword %q must be entirely uppercase or entirely lowercase", s)
		}
		idx, ok := keywordOrder[upper]
		if !ok {
			return parsedEndpoint{}, fmt.Errorf("unknown protocol suffix %q in %q (expected TCP, UDP, or SSL)", s, tok)
		}
		if seen[upper] {
			return parsedEndpoint{}, fmt.Errorf("protocol suffix %q repeated in %q", s, tok)
		}
		if idx <= last {
			return parsedEndpoint{}, fmt.Errorf("protocol suffixes in %q must appear in TCP, UDP, SSL order", tok)
		}
		seen[upper] = true
		last = idx

		switch upper {
		case "TCP":
			pe.tcp = true
		case "UDP":
			pe.udp = true
		case "SSL":
			pe.ep.SSL = true
		}
	}
	return pe, nil
}

// normalizeAddr parses an address token (without any protocol suffix) into
// a normalized "host:port" (or "[host]:port" for IPv6) string.
//
// A listen address may omit the host entirely and be given as a bare port
// (e.g. "8888"), which becomes the IPv4 wildcard "0.0.0.0:8888". A target
// address must always include a port.
func normalizeAddr(tok string, isTarget bool) (string, error) {
	if tok == "" {
		return "", errors.New("empty address")
	}

	if !strings.Contains(tok, ":") {
		if !isAllDigits(tok) {
			return "", fmt.Errorf("address %q is missing a port", tok)
		}
		if isTarget {
			return "", fmt.Errorf("target %q must include a port (host:port)", tok)
		}
		if err := validatePort(tok); err != nil {
			return "", err
		}
		return "0.0.0.0:" + tok, nil
	}

	host, port, err := net.SplitHostPort(tok)
	if err != nil {
		return "", fmt.Errorf("invalid address %q: %w", tok, err)
	}
	if err := validatePort(port); err != nil {
		return "", err
	}
	if host == "" {
		if isTarget {
			return "", fmt.Errorf("target %q must include a host", tok)
		}
		host = "0.0.0.0"
	}
	return net.JoinHostPort(host, port), nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func validatePort(p string) error {
	n, err := strconv.Atoi(p)
	if err != nil {
		return fmt.Errorf("invalid port %q", p)
	}
	if n < 1 || n > 65535 {
		return fmt.Errorf("port %d out of range (1-65535)", n)
	}
	return nil
}

// validateCerts enforces SKILL.md's -key=/-cert=/-signca=/-servername=
// combination rules. sslListen/sslTarget report whether /SSL takes effect
// on the listen (decode) and target (encode) side respectively (TCP TLS
// or UDP DTLS, or both); sslListenUDP separately reports whether the
// listen side's DTLS (UDP) half is active, since -signca= (MITM) only
// covers TLS termination over TCP.
func validateCerts(opts options, sslListen, sslListenUDP, sslTarget bool) error {
	if opts.signCAPath != "" {
		if opts.keyPath != "" || opts.certPath != "" {
			return errors.New("-signca= cannot be combined with -key=/-cert=")
		}
		if !sslListen {
			return errors.New("-signca= requires TLS termination on the listen side (.../SSL on <listen>)")
		}
		if sslListenUDP {
			return errors.New("-signca= does not support DTLS termination over UDP; use -cert=/-key= instead, or drop /UDP from the listen side")
		}
		if sslTarget {
			return errors.New("-signca= cannot be combined with TLS origination toward target (<target>/SSL); use -key=/-cert= instead")
		}
		return nil
	}
	if opts.serverName != "" {
		return errors.New("-servername= requires -signca=")
	}

	if opts.keyPath != "" && opts.certPath == "" {
		return errors.New("-key= was specified without -cert=")
	}
	if (sslListen || sslTarget) && opts.certPath == "" {
		return errors.New("/SSL requires -cert= (or -signca= on the listen side) to be specified")
	}
	if opts.certPath != "" && opts.keyPath == "" {
		embedded, err := tlsutil.HasEmbeddedKey(opts.certPath)
		if err != nil {
			return fmt.Errorf("failed to read -cert=%s: %w", opts.certPath, err)
		}
		if !embedded {
			return fmt.Errorf("-cert=%s does not contain a private key; -key= is required", opts.certPath)
		}
	}
	return nil
}
