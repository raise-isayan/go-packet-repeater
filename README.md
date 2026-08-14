go packet repeter
=============
Language/[Japanese](README-ja.md)

# gopr

`gopr` is a single-binary Go tool for relaying TCP or UDP packets. Its main
features are:

* Listen on a given port and relay traffic to a given destination.
* Terminate or originate TLS along the way (including mutual TLS/mTLS).
* Function as a simple HTTP proxy or a SOCKS5 proxy.

For the full, formal command-line grammar (used as the implementation spec),

## Features

- **TCP and/or UDP forwarding** — either protocol, or both at once, per relay.
- **TLS termination** (decode: TLS → plaintext) and **TLS origination**
  (encode: plaintext → TLS), including **mutual TLS** (client certificate
  request/verification on termination, client certificate presentation on
  origination).
- **MITM-style TLS termination via `-M -signca=`**: mint a server certificate
  on the fly, per connection, from a CA (including its private key) for
  whatever hostname SNI or `-servername=` selects.
- **Independent certificates on each side** (`-Q` for the target side,
  `-Z`/`-M` for the listen side) when both terminate and originate TLS in
  the same relay.
- **IPv4, IPv6, and hostname** addressing, with a bare port shorthand for
  listen addresses (`8888` → `0.0.0.0:8888`).
- **HTTP proxy** and **SOCKS5 proxy** modes as alternatives to forwarding.
- **Multiple targets in one invocation**, separated by `--`, all running
  concurrently in a single process.
- **`-verify=0`** (under `-Q`/`-Z`/`-M`) to skip certificate verification
  (e.g. for self-signed certs during testing).
- **tiered debug logging (`-d`/`-dd`/`-ddd`)** and **`-v`** to
  dump the relayed data itself.
- No config file, no daemon — a single static binary driven entirely by
  command-line arguments.

## Install / Build

Requires Go 1.26+.

```bash
./gradlew build     # builds a binary for the host OS at the project root
```

### Cross-compiled release builds (Gradle)

Builds are done via the Gradle wrapper.

```bash
./gradlew buildAll     # builds every target into dist/
./gradlew releaseAll   # zips each dist/ binary into release/
```

## Usage

```
gopr [option] <target> <listen>

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
  [-d | -dd | -ddd]      ; debug output, each extra d prints
                         ; one more, less severe tier of diagnostics.
  [-v]                   ; dump the relayed data content to stderr,
                         ; independent of -d.
  [-help]                ; show help
  [-version]             ; show version

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
  [-verify=<value>]       ; same as -Z's -verify=
```

- The two positional arguments are always `<target>` then `<listen>` (the
  forwarding destination, then the local address to listen on).
- `-Q`, `-Z`, and `-M` each open a block, at most once apiece, that every
  following `-key=`/`-cert=`/`-ca=`/`-verify=` (under `-Q`/`-Z`) or
  `-signca=`/`-servername=`/`-ca=`/`-verify=` (under `-M`) belongs to, until
  the next `-Q`/`-Z`/`-M` token or the first positional argument. These
  sub-options cannot appear before any block has been opened. `-d`/`-dd`/
  `-ddd`/`-v`/`-help`/`-version` are global and don't affect block scope.
- Options must appear before the positional arguments; `-Q`/`-Z`/`-M` blocks
  may appear in any order, and are all optional.
- `-help` / `-version` print their respective output and exit immediately,
  ignoring any positional arguments; `-help` wins if both are given.

### Multiple targets (`--`)

Separate multiple full `[option] <target> <listen>` groups with `--` to run
them all concurrently from a single `gopr` process:

```bash
gopr 192.0.2.11:7777 8888 -- 192.0.2.11:5555 6666
```

This behaves the same as running two separate commands at once:

```bash
gopr 192.0.2.11:7777 8888
gopr 192.0.2.11:5555 6666
```

### Address notation

| Form | Syntax | Example |
|---|---|---|
| IPv4 | `host:port` | `192.0.2.11:7777` |
| IPv6 | `[host]:port` | `[2001:db8::2]:7777` |
| Hostname (FQDN) | `hostname:port` | `example.com:7777` |
| Listen, interface omitted | `port` only | `8888` → listens on `0.0.0.0:8888` |

`target` always requires a port (except in proxy/socks mode, see below);
`listen` may omit the host and default to the IPv4 wildcard. To listen on
all IPv6 interfaces (and, on most platforms, dual-stack IPv4 too), use
`[::]:port` explicitly.

### Protocol suffixes (`/tcp`, `/udp`, `/ssl`)

Append `/tcp`, `/udp`, and/or `/ssl` to `target` or `listen`, always in that
order. `/tcp` and `/udp` are only valid on `listen` — gopr only relays
TCP→TCP and UDP→UDP, never converts between them, so `target` carrying a
`/tcp` or `/udp` suffix is an error. Default protocol is TCP-only when
nothing is specified. `/ssl` always goes on whichever side speaks encrypted
traffic: `listen` for termination (configured via `-Z`/`-M`), `target` for
origination (configured via `-Q`), and it may appear on either side, or
both at once (see "Double TLS" below), regardless of where `/tcp`/`/udp`
was declared. `/ssl` secures whichever of TCP/UDP are active for that relay
— TLS over TCP, DTLS (via [pion/dtls](https://github.com/pion/dtls)) over
UDP — sharing the same `-key=`/`-cert=`/`-ca=` options within their block.
`-M` (MITM) is TCP-only; combining it with an active `/udp/ssl` on the
listen side is an error.

Suffix keywords may be all-uppercase or all-lowercase (not mixed within one
token), and case may differ between tokens in the same command.

### Double TLS: independent certificates on each side

Putting `/ssl` on both `target` and `listen` terminates the incoming
TLS/DTLS on `listen` and originates a *separate* TLS/DTLS connection toward
`target`, each with its own certificate configuration (`-Z`/`-M` for the
listen side, `-Q` for the target side):

```bash
# Decrypt incoming TLS on 8888, then re-encrypt toward target presenting a
# client certificate and verifying target's certificate against a CA
gopr -Q -key=/client/client.key -cert=/client/client.pem -ca=/server/ca.pem \
     -Z -key=/server/cert.key -cert=/server/cert.pem \
     192.0.2.11:7777/ssl 8888/ssl
```

`-Q` may be omitted entirely — the target side then originates TLS with no
client certificate, verified against the system root CA pool.

### MITM-style TLS termination (`-M`)

Instead of a static `-Z -cert=`/`-key=` pair, a CA file that includes its
own private key (`-M -signca=`) lets gopr mint a fresh server certificate
for each connection and terminate TLS with it:

```bash
gopr -M -signca=/server/ca.pem 192.0.2.11:7777 8888/ssl
```

- The generated certificate's hostname always comes from `-servername=`
  when given; otherwise it comes from that connection's SNI (a connection
  with neither is rejected).
- Keys are RSA 2048-bit, valid for 46 days; certificates are cached per
  hostname for the life of the process.
- `-M` is mutually exclusive with `-Z` (a listen side has either a static
  certificate or a MITM signing CA, never both). It can be combined with
  `-Q` for the target side (double TLS with a dynamically generated
  listen-side certificate), and with `-ca=`/`-verify=` for mTLS.
  `-servername=` requires `-signca=`.
- `-M` covers TCP (TLS) termination only — it does not mint DTLS
  certificates, so combining it with an active `/udp/ssl` on the listen
  side is an error. Use `-Z` with a static `-cert=`/`-key=` pair for DTLS
  instead.

## Examples

```bash
# Forward all interfaces:8888 -> 192.0.2.11:7777, TCP only (default)
gopr 192.0.2.11:7777 8888

# Same, but UDP only
gopr 192.0.2.11:7777 8888/udp

# TCP and UDP together
gopr 192.0.2.11:7777 8888/tcp/udp

# DTLS termination: decrypt incoming DTLS on 8888/udp, forward plaintext to target
gopr -Z -key=/server/cert.key -cert=/server/cert.pem 192.0.2.11:7777 8888/udp/ssl

# TLS+DTLS termination together: TCP gets TLS, UDP gets DTLS, same cert
gopr -Z -key=/server/cert.key -cert=/server/cert.pem 192.0.2.11:7777 8888/tcp/udp/ssl

# Hostname target, IPv6 listen on all interfaces
gopr backend.internal:7777 [::]:8888

# TLS termination: decrypt incoming TLS on 8888, forward plaintext to target
gopr -Z -key=/server/cert.key -cert=/server/cert.pem 192.0.2.11:7777 8888/ssl

# TLS termination, cert file has an embedded private key (-key= omitted)
gopr -Z -cert=/server/cert.pem 192.0.2.11:7777 8888/ssl

# TLS termination + mutual TLS (require & verify a client certificate)
gopr -Z -key=/server/cert.key -cert=/server/cert.pem -ca=/client/client-ca.pem \
     192.0.2.11:7777 8888/ssl

# TLS origination: accept plaintext on 8888, encrypt on the way to target,
# no client certificate needed
gopr 192.0.2.11:7777/ssl 8888

# TLS origination with a client certificate, verifying the server against a CA
gopr -Q -key=/client/client.key -cert=/client/client.pem -ca=/server/ca.pem \
     192.0.2.11:7777/ssl 8888

# Skip TLS certificate verification (e.g. self-signed server cert)
gopr -Q -verify=0 192.0.2.11:7777/ssl 8888

# TLS termination + MITM (certificate minted from the client's SNI)
gopr -M -signca=/server/ca.pem 192.0.2.11:7777 8888/ssl

# TLS termination + MITM with a fixed hostname
gopr -M -signca=/server/ca.pem -servername=example.com 192.0.2.11:7777 8888/ssl

# TLS termination with a different certificate on each side (double TLS)
gopr -Q -key=/client/client.key -cert=/client/client.pem -ca=/server/ca.pem \
     -Z -key=/server/cert.key -cert=/server/cert.pem \
     192.0.2.11:7777/ssl 8888/ssl

# HTTP proxy on 8888
gopr proxy 8888

# SOCKS5 proxy on 8888
gopr socks 8888

# HTTP proxy on 8888, chained to an upstream HTTP proxy (192.0.2.11:7777)
gopr 192.0.2.11:7777/proxy 8888

# SOCKS5 proxy on 8888, chained to an upstream SOCKS proxy (192.0.2.11:7777)
gopr 192.0.2.11:7777/socks 8888

# Two relays from one process (see "Multiple targets" above)
gopr 192.0.2.11:7777 8888 -- 192.0.2.11:5555 6666

gopr -help
gopr -version
```

## Options reference

| Option | Meaning | Required? |
|---|---|---|
| `-Q` | Opens the SSL client block: TLS/DTLS origination toward `target` | Optional; requires `<target>/SSL` when given |
| `-Z` | Opens the SSL server block: static TLS/DTLS termination on `listen` | Optional; requires `<listen>/SSL` when given. Mutually exclusive with `-M` |
| `-M` | Opens the SSL server MITM block: generated-certificate termination on `listen` | Optional; requires `<listen>/SSL` when given, TCP only. Mutually exclusive with `-Z` |
| `-key=<path>` (under `-Q`/`-Z`) | Private key for that side | Only if `-cert=` has no embedded key |
| `-cert=<path>` (under `-Q`/`-Z`) | Certificate for that side | Optional under `-Q`; required under `-Z` unless `-M` is used instead |
| `-ca=<path>` (under `-Q`/`-Z`/`-M`) | CA used to verify the *peer's* certificate | Optional — under `-Q`, verifies the target's certificate; under `-Z`/`-M`, requests and verifies a client certificate (mTLS) |
| `-verify=<value>` (under `-Q`/`-Z`/`-M`) | `verify=0`: under `-Q`, skip verifying the target's certificate; under `-Z`/`-M`, still require a client certificate but skip verifying it against `-ca=` | Optional, defaults to verifying |
| `-signca=<path>` (under `-M`) | CA (cert + private key) used to mint a leaf certificate per connection for TLS termination | Required under `-M` |
| `-servername=<value>` (under `-M`) | Hostname for the generated certificate; defaults to the connection's SNI | Only meaningful with `-signca=` |
| `-d` / `-dd` / `-ddd` | Debug output, `-d` adds connection/session lifecycle notices, `-dd` adds per-connection detail and byte counts, `-ddd` adds per-chunk/per-packet trace | Optional, defaults to errors only |
| `-v` | Dump the actual data relayed between target and listen to stderr, independent of `-d` | Optional |
| `-help` | Print usage and exit | — |
| `-version` | Print version and exit | — |

## proxy / socks modes

If `target` is exactly the literal `proxy` or `socks` (any consistent
casing, e.g. `PROXY`), with no port, `listen` is used as the address for an
HTTP proxy or SOCKS5 proxy, respectively, and normal forwarding is bypassed
entirely. These modes cannot be combined with `-Q`/`-Z`/`-M` (or their
sub-options) or any `/tcp`, `/udp`, `/ssl` suffix (`-d`/`-dd`/`-ddd`/`-v`
remain usable).

### Chaining to an upstream proxy (`<host:port>/proxy`, `<host:port>/socks`)

Giving `target` as `<host:port>/proxy` or `<host:port>/socks` instead of the
bare keyword chains the proxy to an upstream server of the same kind
instead of dialing each client's requested destination directly: `/proxy`
relays through an upstream HTTP proxy, `/socks` through an upstream SOCKS5
server. The upstream is always the same kind as the local listen mode —
there's no syntax for mixing (e.g. an HTTP proxy chaining to an upstream
SOCKS server).

```bash
# HTTP proxy on 8888, chained to an upstream HTTP proxy
gopr 192.0.2.11:7777/proxy 8888

# SOCKS5 proxy on 8888, chained to an upstream SOCKS proxy
gopr 192.0.2.11:7777/socks 8888
```

- `<host:port>` requires a port, same as a normal `target`.
- The same restrictions as the bare keyword form apply: no `-Q`/`-Z`/`-M`
  (or their sub-options) or `/tcp`/`/udp`/`/ssl` suffixes (`-d`/`-dd`/`-ddd`/
  `-v` remain usable).
- Authentication (HTTP Basic, SOCKS5 username/password) and TLS to the
  upstream (i.e. an HTTPS proxy) are not supported yet; the upstream is
  assumed to be unauthenticated and unencrypted.
- SOCKS chaining still only supports CONNECT, matching the existing SOCKS
  server implementation (no BIND, no UDP ASSOCIATE).

## Limitations

- **`-M` (MITM) is TCP-only.** DTLS termination on the UDP side always
  requires a static `-Z -cert=`/`-key=` pair.
- Binding "all interfaces for IPv4, one specific address for IPv6"
  asymmetrically in a single relay isn't expressible — run two `gopr`
  processes instead.

including every validated edge case and error condition.
