package proxy

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// digestChallenge is a parsed "Digest ..." WWW-Authenticate/Proxy-Authenticate
// challenge (RFC 2617 / RFC 7616), as offered by an upstream HTTP proxy that
// wants Digest instead of (or in addition to) Basic auth.
type digestChallenge struct {
	realm     string
	nonce     string
	opaque    string
	algorithm string // "", "MD5", or "MD5-sess" ("" is treated as MD5)
	qop       string // "auth" if the server offers it, else ""
}

// findDigestChallenge scans a set of Proxy-Authenticate (or WWW-Authenticate)
// header values -- a challenging response may list more than one scheme,
// one header per scheme -- and returns the first Digest challenge found.
func findDigestChallenge(headers []string) (digestChallenge, bool) {
	for _, h := range headers {
		if ch, ok := parseDigestChallenge(h); ok {
			return ch, true
		}
	}
	return digestChallenge{}, false
}

// parseDigestChallenge parses a single challenge header value, returning
// ok=false if it is not a Digest challenge.
func parseDigestChallenge(header string) (digestChallenge, bool) {
	scheme, rest, _ := strings.Cut(strings.TrimSpace(header), " ")
	if !strings.EqualFold(scheme, "Digest") {
		return digestChallenge{}, false
	}

	var ch digestChallenge
	for _, param := range splitAuthParams(rest) {
		key, value, ok := strings.Cut(param, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"`)
		switch strings.ToLower(key) {
		case "realm":
			ch.realm = value
		case "nonce":
			ch.nonce = value
		case "opaque":
			ch.opaque = value
		case "algorithm":
			ch.algorithm = value
		case "qop":
			for _, q := range strings.Split(value, ",") {
				if strings.TrimSpace(q) == "auth" {
					ch.qop = "auth"
				}
			}
		}
	}
	if ch.nonce == "" {
		return digestChallenge{}, false
	}
	return ch, true
}

// splitAuthParams splits a comma-separated list of "key=value" or
// key="quoted, value" pairs, respecting commas embedded in quoted strings.
func splitAuthParams(s string) []string {
	var params []string
	var cur strings.Builder
	inQuotes := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuotes = !inQuotes
			cur.WriteRune(r)
		case r == ',' && !inQuotes:
			params = append(params, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		params = append(params, cur.String())
	}
	return params
}

// buildDigestAuthorization computes a Proxy-Authorization: Digest header
// value for ch in response to a request of the given method/uri, per
// RFC 2617 (RFC 7616's MD5/MD5-sess case; SHA-256 and userhash are not
// supported, matching what upstream HTTP proxies commonly require).
func buildDigestAuthorization(ch digestChallenge, method, uri, user, pass string) (string, error) {
	algorithm := ch.algorithm
	if algorithm == "" {
		algorithm = "MD5"
	}
	if !strings.EqualFold(algorithm, "MD5") && !strings.EqualFold(algorithm, "MD5-sess") {
		return "", fmt.Errorf("digest auth: unsupported algorithm %q", ch.algorithm)
	}

	cnonce, err := randomHex(16)
	if err != nil {
		return "", fmt.Errorf("digest auth: %w", err)
	}

	ha1 := md5Hex(user + ":" + ch.realm + ":" + pass)
	if strings.EqualFold(algorithm, "MD5-sess") {
		ha1 = md5Hex(ha1 + ":" + ch.nonce + ":" + cnonce)
	}
	ha2 := md5Hex(method + ":" + uri)

	const nc = "00000001"
	var response string
	if ch.qop != "" {
		response = md5Hex(strings.Join([]string{ha1, ch.nonce, nc, cnonce, ch.qop, ha2}, ":"))
	} else {
		response = md5Hex(ha1 + ":" + ch.nonce + ":" + ha2)
	}

	var b strings.Builder
	fmt.Fprintf(&b, `Digest username=%q, realm=%q, nonce=%q, uri=%q, response=%q`,
		user, ch.realm, ch.nonce, uri, response)
	if ch.opaque != "" {
		fmt.Fprintf(&b, `, opaque=%q`, ch.opaque)
	}
	if ch.algorithm != "" {
		fmt.Fprintf(&b, `, algorithm=%s`, algorithm)
	}
	if ch.qop != "" {
		fmt.Fprintf(&b, `, qop=%s, nc=%s, cnonce=%q`, ch.qop, nc, cnonce)
	}
	return b.String(), nil
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
