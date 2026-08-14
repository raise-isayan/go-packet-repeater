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
  [-Q <SSL>]              ; SSL client option: TLS/DTLS origination toward
                          ; <target>. Requires <target>/SSL.
  [-Z <SSL>]              ; SSL server option: static TLS/DTLS termination
                          ; on <listen>. Requires <listen>/SSL. Mutually
                          ; exclusive with -M.
  [-M <MITM>]             ; SSL server MITM option: per-connection generated
                          ; certificate for TLS termination on <listen>,
                          ; instead of -Z's static certificate. Requires
                          ; <listen>/SSL; TCP only. Mutually exclusive
                          ; with -Z.
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
  [-version]              ; show version

<SSL>                     ; sub-options of -Q / -Z, in either order
  [-key=<path>]           ; this side's own key file
  [-cert=<path>]          ; this side's own cert file (optional under -Q;
                          ; required under -Z unless -M is used instead)
  [-ca=<path>]            ; CA verifying the peer's certificate (under -Q:
                          ; the target's cert; under -Z: requests and
                          ; verifies a client cert, i.e. mTLS)
  [-verify=<value>]       ; verify=0: under -Q, don't verify the target's
                          ; certificate; under -Z, still require a client
                          ; certificate (when -ca= is set) but don't verify
                          ; it against -ca=

<MITM>                    ; sub-options of -M, in any order
  [-signca=<path>]        ; CA (cert + private key) used to mint a leaf
                          ; certificate per connection for TLS termination
  [-servername=<value>]   ; hostname for the generated certificate;
                          ; overrides the client's SNI
  [-ca=<path>]            ; same as -Z's -ca= (mTLS)
  [-verify=<value>]       ; same as -Z's -verify=`

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

	if mode, upstream, isProxy, perr := classifyProxyTarget(targetTok); isProxy {
		if perr != nil {
			return nil, perr
		}
		if opts.q.seen || opts.z.seen || opts.m.seen {
			return nil, errors.New("proxy/socks mode cannot be combined with -Q/-Z/-M")
		}
		if strings.Contains(listenTok, "/") {
			return nil, fmt.Errorf("proxy/socks mode cannot be combined with protocol suffixes: %q", listenTok)
		}
		addr, err := normalizeAddr(listenTok, false)
		if err != nil {
			return nil, err
		}
		return &Config{
			Mode:         mode,
			Listen:       Endpoint{Addr: addr, TCP: true},
			UpstreamAddr: upstream,
			LogLevel:     opts.logLevel,
			Verbose:      opts.verbose,
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

	// TCP/UDP are properties of the relay as a whole, and may only be
	// declared on the listen side (see parseEndpoint). Default to TCP-only
	// when the listen side says nothing.
	tcp := listen.tcp
	udp := listen.udp
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
	if err := validateSSL(opts, sslListen, sslListenUDP, sslTarget); err != nil {
		return nil, err
	}

	return &Config{
		Mode:   ModeForward,
		Target: target.ep,
		Listen: listen.ep,
		ClientTLS: ClientTLSConfig{
			KeyPath:  opts.q.keyPath,
			CertPath: opts.q.certPath,
			CAPath:   opts.q.caPath,
			Verify:   opts.q.verify,
		},
		ServerTLS: ServerTLSConfig{
			KeyPath:      opts.z.keyPath,
			CertPath:     opts.z.certPath,
			CAPath:       opts.z.caPath,
			VerifyClient: opts.z.verify,
		},
		MITM: MITMConfig{
			SignCAPath:   opts.m.signCAPath,
			ServerName:   opts.m.serverName,
			CAPath:       opts.m.caPath,
			VerifyClient: opts.m.verify,
		},
		LogLevel: opts.logLevel,
		Verbose:  opts.verbose,
	}, nil
}

// sslScope accumulates the -key=/-cert=/-ca=/-verify= sub-options given
// under a -Q or -Z block (see sslBlockScope). verify defaults to true; it
// is false only when -verify=0 was given within this block.
type sslScope struct {
	keyPath, certPath, caPath string
	verify                    bool
	// seen reports whether the block's own -Q/-Z token was given at all,
	// regardless of whether any sub-options followed it.
	seen bool
}

// mitmScope accumulates the -signca=/-servername=/-ca=/-verify=
// sub-options given under a -M block.
type mitmScope struct {
	signCAPath, serverName, caPath string
	verify                         bool
	seen                           bool
}

// options holds every -flag= gopr accepts, before the target/listen
// positional arguments have been parsed.
type options struct {
	q sslScope  // -Q <SSL>: TLS/DTLS origination toward <target>
	z sslScope  // -Z <SSL>: static TLS/DTLS termination on <listen>
	m mitmScope // -M <MITM>: generated-certificate termination on <listen>

	help, version bool
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

// sslScopeKind identifies which of -Q/-Z/-M block is currently open while
// walking the option tokens, so a following -key=/-cert=/-ca=/-verify=/
// -signca=/-servername= sub-option is assigned to the right one.
type sslScopeKind int

const (
	scopeNone sslScopeKind = iota
	scopeQ
	scopeZ
	scopeM
)

// extractOptions consumes leading option tokens (any order) and returns the
// remaining positional arguments.
//
// -Q, -Z, and -M each open a scope, at most once apiece, that every
// following -key=/-cert=/-ca=/-verify= (under -Q or -Z) or -signca=/
// -servername=/-ca=/-verify= (under -M) sub-option belongs to, until the
// next -Q/-Z/-M token or the first positional argument. A sub-option
// appearing before any scope has been opened is an error. -d/-dd/-ddd/-v/
// -help/-version are global and do not open or close a scope; they may
// appear anywhere among the option tokens, including inside a -Q/-Z/-M
// block, without affecting it.
//
// verify defaults to true within each scope; it is false only when
// -verify=0 was given inside that scope.
func extractOptions(args []string) (options, []string, error) {
	opts := options{}
	opts.q.verify, opts.z.verify, opts.m.verify = true, true, true
	scope := scopeNone

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
		case tok == "-Q":
			if opts.q.seen {
				return options{}, nil, errors.New("-Q specified more than once")
			}
			opts.q.seen = true
			scope = scopeQ
		case tok == "-Z":
			if opts.z.seen {
				return options{}, nil, errors.New("-Z specified more than once")
			}
			opts.z.seen = true
			scope = scopeZ
		case tok == "-M":
			if opts.m.seen {
				return options{}, nil, errors.New("-M specified more than once")
			}
			opts.m.seen = true
			scope = scopeM
		case strings.HasPrefix(tok, "-key="):
			val := strings.TrimPrefix(tok, "-key=")
			switch scope {
			case scopeQ:
				if opts.q.keyPath != "" {
					return options{}, nil, errors.New("-Q -key= specified more than once")
				}
				opts.q.keyPath = val
			case scopeZ:
				if opts.z.keyPath != "" {
					return options{}, nil, errors.New("-Z -key= specified more than once")
				}
				opts.z.keyPath = val
			default:
				return options{}, nil, errors.New("-key= requires -Q or -Z before it")
			}
		case strings.HasPrefix(tok, "-cert="):
			val := strings.TrimPrefix(tok, "-cert=")
			switch scope {
			case scopeQ:
				if opts.q.certPath != "" {
					return options{}, nil, errors.New("-Q -cert= specified more than once")
				}
				opts.q.certPath = val
			case scopeZ:
				if opts.z.certPath != "" {
					return options{}, nil, errors.New("-Z -cert= specified more than once")
				}
				opts.z.certPath = val
			default:
				return options{}, nil, errors.New("-cert= requires -Q or -Z before it")
			}
		case strings.HasPrefix(tok, "-ca="):
			val := strings.TrimPrefix(tok, "-ca=")
			switch scope {
			case scopeQ:
				if opts.q.caPath != "" {
					return options{}, nil, errors.New("-Q -ca= specified more than once")
				}
				opts.q.caPath = val
			case scopeZ:
				if opts.z.caPath != "" {
					return options{}, nil, errors.New("-Z -ca= specified more than once")
				}
				opts.z.caPath = val
			case scopeM:
				if opts.m.caPath != "" {
					return options{}, nil, errors.New("-M -ca= specified more than once")
				}
				opts.m.caPath = val
			default:
				return options{}, nil, errors.New("-ca= requires -Q, -Z, or -M before it")
			}
		case strings.HasPrefix(tok, "-verify="):
			val := strings.TrimPrefix(tok, "-verify=") != "0"
			switch scope {
			case scopeQ:
				opts.q.verify = val
			case scopeZ:
				opts.z.verify = val
			case scopeM:
				opts.m.verify = val
			default:
				return options{}, nil, errors.New("-verify= requires -Q, -Z, or -M before it")
			}
		case strings.HasPrefix(tok, "-signca="):
			if scope != scopeM {
				return options{}, nil, errors.New("-signca= requires -M before it")
			}
			if opts.m.signCAPath != "" {
				return options{}, nil, errors.New("-M -signca= specified more than once")
			}
			opts.m.signCAPath = strings.TrimPrefix(tok, "-signca=")
		case strings.HasPrefix(tok, "-servername="):
			if scope != scopeM {
				return options{}, nil, errors.New("-servername= requires -M before it")
			}
			if opts.m.serverName != "" {
				return options{}, nil, errors.New("-M -servername= specified more than once")
			}
			opts.m.serverName = strings.TrimPrefix(tok, "-servername=")
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

// classifyProxyTarget reports whether targetTok selects proxy/socks mode,
// in either of two forms:
//
//   - the bare keyword ("proxy" / "socks", see proxyMode): dial each
//     client's requested destination directly, no upstream.
//   - "<host:port>/proxy" or "<host:port>/socks": chain to the given
//     upstream proxy/SOCKS server instead of dialing directly. The
//     upstream is always the same kind as the local listen mode (an
//     HTTP proxy chains only to an upstream HTTP proxy, SOCKS only to
//     upstream SOCKS) -- there is no syntax for mixing kinds.
//
// ok reports whether targetTok matched either form at all; when it does
// but the upstream address is invalid, ok is still true and err explains
// why (the caller should surface it rather than falling through to
// normal <target> endpoint parsing, which would produce a confusing
// unrelated error). When ok is false, targetTok is not a proxy/socks
// target of any kind and the caller should parse it as a normal
// forwarding endpoint.
func classifyProxyTarget(targetTok string) (mode Mode, upstream string, ok bool, err error) {
	if m, matched := proxyMode(targetTok); matched {
		return m, "", true, nil
	}

	idx := strings.IndexByte(targetTok, '/')
	if idx < 0 {
		return 0, "", false, nil
	}
	addrTok, suffix := targetTok[:idx], targetTok[idx+1:]
	// Only a single "/proxy" or "/socks" suffix triggers chain mode; a
	// token like "host:port/tcp/proxy" or "host:port/proxy/ssl" falls
	// through so normal endpoint parsing reports its own (accurate)
	// error about the unsupported suffix combination.
	if strings.Contains(suffix, "/") {
		return 0, "", false, nil
	}
	m, matched := proxyMode(suffix)
	if !matched {
		return 0, "", false, nil
	}

	addr, err := normalizeAddr(addrTok, true)
	if err != nil {
		return 0, "", true, fmt.Errorf("invalid upstream address %q: %w", addrTok, err)
	}
	return m, addr, true, nil
}

// parsedEndpoint carries the boolean TCP/UDP suffix presence separately
// from the final Endpoint. Only the listen token may carry /TCP or /UDP
// (see parseEndpoint); the final TCP/UDP flags mirror the listen side and
// are applied to both target.ep and listen.ep once parsing is done.
type parsedEndpoint struct {
	ep       Endpoint
	tcp, udp bool
}

// parseEndpoint splits tok into its address and "/TCP" "/UDP" "/SSL"
// suffixes, and validates each part. /TCP and /UDP are only valid on the
// listen token (isTarget == false); a target token carrying either is an
// error. /SSL is valid on both.
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
		if isTarget && (upper == "TCP" || upper == "UDP") {
			return parsedEndpoint{}, fmt.Errorf("protocol suffix %q not allowed on <target> (%q); specify /TCP and/or /UDP on <listen> instead", s, tok)
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

// validateSSL enforces SKILL.md's -Q/-Z/-M combination rules. sslListen/
// sslTarget report whether /SSL takes effect on the listen (decode) and
// target (encode) side respectively (TCP TLS or UDP DTLS, or both);
// sslListenUDP separately reports whether the listen side's DTLS (UDP)
// half is active, since -M (MITM) only covers TLS termination over TCP.
func validateSSL(opts options, sslListen, sslListenUDP, sslTarget bool) error {
	if opts.z.seen && opts.m.seen {
		return errors.New("-Z and -M cannot both be specified (mutually exclusive server-side TLS options)")
	}
	if opts.q.seen && !sslTarget {
		return errors.New("-Q requires TLS/DTLS origination toward target (<target>/SSL)")
	}
	if opts.z.seen && !sslListen {
		return errors.New("-Z requires TLS/DTLS termination on listen (<listen>/SSL)")
	}
	if opts.m.seen && !sslListen {
		return errors.New("-M requires TLS termination on listen (<listen>/SSL)")
	}
	if opts.m.seen && sslListenUDP {
		return errors.New("-M does not support DTLS termination over UDP; use -Z with -key=/-cert= instead, or drop /UDP from the listen side")
	}
	if opts.m.serverName != "" && opts.m.signCAPath == "" {
		return errors.New("-M -servername= requires -M -signca=")
	}

	if err := validateSSLKeyCert("-Q", opts.q.keyPath, opts.q.certPath); err != nil {
		return err
	}
	if err := validateSSLKeyCert("-Z", opts.z.keyPath, opts.z.certPath); err != nil {
		return err
	}
	if sslListen && opts.z.certPath == "" && opts.m.signCAPath == "" {
		return errors.New("<listen>/SSL requires -Z -cert= (or -M -signca=) to be specified")
	}
	return nil
}

// validateSSLKeyCert enforces the -key=/-cert= pairing rule shared by -Q
// and -Z's blocks: -key= alone is an error, and a -cert= without -key=
// must embed its own private key. label ("-Q" or "-Z") only decorates the
// error messages.
func validateSSLKeyCert(label, keyPath, certPath string) error {
	if keyPath != "" && certPath == "" {
		return fmt.Errorf("%s -key= was specified without -cert=", label)
	}
	if certPath != "" && keyPath == "" {
		embedded, err := tlsutil.HasEmbeddedKey(certPath)
		if err != nil {
			return fmt.Errorf("failed to read %s -cert=%s: %w", label, certPath, err)
		}
		if !embedded {
			return fmt.Errorf("%s -cert=%s does not contain a private key; -key= is required", label, certPath)
		}
	}
	return nil
}
