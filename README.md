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
- **MITM-style TLS termination via `-signca=`**: mint a server certificate
  on the fly, per connection, from a CA (including its private key) for
  whatever hostname SNI or `-servername=` selects.
- **IPv4, IPv6, and hostname** addressing, with a bare port shorthand for
  listen addresses (`8888` → `0.0.0.0:8888`).
- **HTTP proxy** and **SOCKS5 proxy** modes as alternatives to forwarding.
- **Multiple targets in one invocation**, separated by `--`, all running
  concurrently in a single process.
- **`-verify=0`** to skip TLS certificate verification (e.g. for self-signed
  certs during testing).
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
./gradlew goBuildAll     # builds every target into dist/
./gradlew goReleaseAll   # zips each dist/ binary into release/
```

## Usage

```
gopr [option] <target> <listen>

[option]
  [-key=<path>]          ; key file
  [-cert=<path>]         ; cert file
  [-ca=<path>]           ; ca file
  [-verify=<value>]      ; verify=0 Do not verify the TLS certificate.
  [-signca=<path>]       ; CA (cert + private key) to mint a per-connection
                         ; leaf certificate for TLS termination (MITM).
  [-servername=<value>]  ; hostname for the generated certificate.
  [-d | -dd | -ddd]      ; debug output, each extra d prints
                         ; one more, less severe tier of diagnostics.
  [-v]                   ; dump the relayed data content to stderr,
                         ; independent of -d.
  [-help]                ; show help
  [-version]             ; show version
```

- The two positional arguments are always `<target>` then `<listen>` (the
  forwarding destination, then the local address to listen on).
- Options must appear before the positional arguments, in any order, and are
  all optional.
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
traffic: `listen` for termination, `target` for origination, and it may
appear on either side regardless of where `/tcp`/`/udp` was declared. `/ssl`
secures whichever of TCP/UDP are active for that relay — TLS over TCP, DTLS
(via [pion/dtls](https://github.com/pion/dtls)) over UDP — sharing the same
`-cert=`/`-key=`/`-ca=` options. `-signca=` (MITM) is TCP-only; combining it
with an active `/udp/ssl` on the listen side is an error.

Suffix keywords may be all-uppercase or all-lowercase (not mixed within one
token), and case may differ between tokens in the same command.

### MITM-style TLS termination (`-signca=`)

Instead of a static `-cert=`/`-key=` pair, a CA file that includes its own
private key (`-signca=`) lets gopr mint a fresh server certificate for each
connection and terminate TLS with it:

```bash
gopr -signca=/server/ca.pem 192.0.2.11:7777 8888/ssl
```

- The generated certificate's hostname always comes from `-servername=`
  when given; otherwise it comes from that connection's SNI (a connection
  with neither is rejected).
- Keys are RSA 2048-bit, valid for 46 days; certificates are cached per
  hostname for the life of the process.
- `-signca=` cannot be combined with `-key=`/`-cert=`, and only applies to
  `/ssl` on the listen side (not the target side). It can be combined with
  `-ca=` for mTLS. `-servername=` requires `-signca=`.
- `-signca=` covers TCP (TLS) termination only — it does not mint DTLS
  certificates, so combining it with an active `/udp/ssl` on the listen
  side is an error. Use a static `-cert=`/`-key=` pair for DTLS instead.

## Examples

```bash
# Forward all interfaces:8888 -> 192.0.2.11:7777, TCP only (default)
gopr 192.0.2.11:7777 8888

# Same, but UDP only
gopr 192.0.2.11:7777 8888/udp

# TCP and UDP together
gopr 192.0.2.11:7777 8888/tcp/udp

# DTLS termination: decrypt incoming DTLS on 8888/udp, forward plaintext to target
gopr -key=/server/cert.key -cert=/server/cert.pem 192.0.2.11:7777 8888/udp/ssl

# TLS+DTLS termination together: TCP gets TLS, UDP gets DTLS, same cert
gopr -key=/server/cert.key -cert=/server/cert.pem 192.0.2.11:7777 8888/tcp/udp/ssl

# Hostname target, IPv6 listen on all interfaces
gopr backend.internal:7777 [::]:8888

# TLS termination: decrypt incoming TLS on 8888, forward plaintext to target
gopr -key=/server/cert.key -cert=/server/cert.pem 192.0.2.11:7777 8888/ssl

# TLS termination, cert file has an embedded private key (-key= omitted)
gopr -cert=/server/cert.pem 192.0.2.11:7777 8888/ssl

# TLS termination + mutual TLS (require & verify a client certificate)
gopr -key=/server/cert.key -cert=/server/cert.pem -ca=/client/client-ca.pem \
     192.0.2.11:7777 8888/ssl

# TLS origination: accept plaintext on 8888, encrypt on the way to target
gopr 192.0.2.11:7777/ssl 8888

# TLS origination with a client certificate, verifying the server against a CA
gopr -key=/client/client.key -cert=/client/client.pem -ca=/server/ca.pem \
     192.0.2.11:7777/ssl 8888

# Skip TLS certificate verification (e.g. self-signed server cert)
gopr -verify=0 192.0.2.11:7777/ssl 8888

# TLS termination + MITM (certificate minted from the client's SNI)
gopr -signca=/server/ca.pem 192.0.2.11:7777 8888/ssl

# TLS termination + MITM with a fixed hostname
gopr -signca=/server/ca.pem -servername=example.com 192.0.2.11:7777 8888/ssl

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
| `-key=<path>` | Private key for the side that speaks TLS/DTLS | Only if `-cert=` has no embedded key |
| `-cert=<path>` | Certificate for the side that speaks TLS/DTLS | Required whenever `/ssl` is used |
| `-ca=<path>` | CA used to verify the *peer's* certificate | Optional — enables mTLS on termination, or pins the trusted CA on origination. Combinable with `-signca=` |
| `-verify=<value>` | `-verify=0` disables TLS certificate verification entirely | Optional, defaults to verifying |
| `-signca=<path>` | CA (cert + private key) used to mint a leaf certificate per connection for TLS termination (MITM) | Optional. Mutually exclusive with `-key=`/`-cert=`; only valid for `/ssl` on the listen side |
| `-servername=<value>` | Hostname for the generated certificate; defaults to the connection's SNI | Only meaningful with `-signca=` |
| `-d` / `-dd` / `-ddd` | Debug output, `-d` adds connection/session lifecycle notices, `-dd` adds per-connection detail and byte counts, `-ddd` adds per-chunk/per-packet trace | Optional, defaults to errors only |
| `-v` | Dump the actual data relayed between target and listen to stderr, independent of `-d` | Optional |
| `-help` | Print usage and exit | — |
| `-version` | Print version and exit | — |

## proxy / socks modes

If `target` is exactly the literal `proxy` or `socks` (any consistent
casing, e.g. `PROXY`), with no port, `listen` is used as the address for an
HTTP proxy or SOCKS5 proxy, respectively, and normal forwarding is bypassed
entirely. These modes cannot be combined with `-key=`/`-cert=`/`-ca=`/
`-verify=`/`-signca=`/`-servername=` or any `/tcp`, `/udp`, `/ssl` suffix
(`-d`/`-dd`/`-ddd`/`-v` remain usable).

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
- The same restrictions as the bare keyword form apply: no `-key=`/`-cert=`/
  `-ca=`/`-verify=`/`-signca=`/`-servername=` or `/tcp`/`/udp`/`/ssl`
  suffixes (`-d`/`-dd`/`-ddd`/`-v` remain usable).
- Authentication (HTTP Basic, SOCKS5 username/password) and TLS to the
  upstream (i.e. an HTTPS proxy) are not supported yet; the upstream is
  assumed to be unauthenticated and unencrypted.
- SOCKS chaining still only supports CONNECT, matching the existing SOCKS
  server implementation (no BIND, no UDP ASSOCIATE).

## Limitations

- **`-signca=` (MITM) is TCP-only.** DTLS termination on the UDP side
  always requires a static `-cert=`/`-key=` pair.
- Binding "all interfaces for IPv4, one specific address for IPv6"
  asymmetrically in a single relay isn't expressible — run two `gopr`
  processes instead.

including every validated edge case and error condition.
