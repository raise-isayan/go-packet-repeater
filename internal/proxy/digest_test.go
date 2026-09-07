package proxy

import (
	"strings"
	"testing"
)

func TestParseDigestChallenge(t *testing.T) {
	t.Run("basic scheme is not a digest challenge", func(t *testing.T) {
		if _, ok := parseDigestChallenge(`Basic realm="test"`); ok {
			t.Fatal("expected ok=false for Basic scheme")
		}
	})

	t.Run("parses quoted params and qop list", func(t *testing.T) {
		ch, ok := parseDigestChallenge(`Digest realm="test realm", nonce="abc123", opaque="xyz", qop="auth,auth-int", algorithm=MD5`)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if ch.realm != "test realm" || ch.nonce != "abc123" || ch.opaque != "xyz" || ch.qop != "auth" || ch.algorithm != "MD5" {
			t.Fatalf("unexpected challenge: %+v", ch)
		}
	})

	t.Run("missing nonce is invalid", func(t *testing.T) {
		if _, ok := parseDigestChallenge(`Digest realm="test"`); ok {
			t.Fatal("expected ok=false without a nonce")
		}
	})

	t.Run("no qop offered leaves qop empty", func(t *testing.T) {
		ch, ok := parseDigestChallenge(`Digest realm="test", nonce="abc123"`)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if ch.qop != "" {
			t.Fatalf("qop = %q, want empty", ch.qop)
		}
	})
}

func TestFindDigestChallenge(t *testing.T) {
	t.Run("picks the Digest header among several schemes", func(t *testing.T) {
		ch, ok := findDigestChallenge([]string{`Basic realm="test"`, `Digest realm="test", nonce="n1"`})
		if !ok || ch.nonce != "n1" {
			t.Fatalf("got ch=%+v ok=%v, want nonce=n1", ch, ok)
		}
	})

	t.Run("no digest challenge present", func(t *testing.T) {
		if _, ok := findDigestChallenge([]string{`Basic realm="test"`}); ok {
			t.Fatal("expected ok=false")
		}
	})
}

func TestBuildDigestAuthorization(t *testing.T) {
	ch := digestChallenge{realm: "test realm", nonce: "abc123", opaque: "op1", qop: "auth"}

	header, err := buildDigestAuthorization(ch, "CONNECT", "example.com:443", "alice", "s3cret")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, ok := parseDigestChallenge(header)
	if !ok {
		t.Fatalf("built header does not parse as Digest: %q", header)
	}
	if got.realm != ch.realm || got.nonce != ch.nonce || got.opaque != ch.opaque {
		t.Fatalf("round-tripped challenge fields = %+v, want realm/nonce/opaque matching %+v", got, ch)
	}

	cnonce := extractParam(t, header, "cnonce")
	nc := extractParam(t, header, "nc")
	response := extractParam(t, header, "response")
	uri := extractParam(t, header, "uri")
	if uri != "example.com:443" {
		t.Fatalf("uri = %q, want %q", uri, "example.com:443")
	}

	ha1 := md5Hex("alice:test realm:s3cret")
	ha2 := md5Hex("CONNECT:example.com:443")
	want := md5Hex(ha1 + ":" + ch.nonce + ":" + nc + ":" + cnonce + ":auth:" + ha2)
	if response != want {
		t.Fatalf("response = %q, want %q", response, want)
	}
}

func TestBuildDigestAuthorizationUnsupportedAlgorithm(t *testing.T) {
	ch := digestChallenge{realm: "test", nonce: "abc123", algorithm: "SHA-256"}
	if _, err := buildDigestAuthorization(ch, "GET", "/", "alice", "s3cret"); err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

// extractParam pulls a single key="value" (or key=value) parameter out of a
// "Digest ..." header for assertions, failing the test if it's absent.
func extractParam(t *testing.T, header, key string) string {
	t.Helper()
	for _, p := range splitAuthParams(strings.TrimPrefix(header, "Digest ")) {
		k, v, ok := strings.Cut(p, "=")
		if ok && strings.TrimSpace(k) == key {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	t.Fatalf("param %q not found in header %q", key, header)
	return ""
}
