package config

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func writePEM(t *testing.T, dir, name string, blocks ...*pem.Block) string {
	t.Helper()
	var data []byte
	for _, b := range blocks {
		data = append(data, pem.EncodeToMemory(b)...)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func certBlock() *pem.Block  { return &pem.Block{Type: "CERTIFICATE", Bytes: []byte("fake-cert")} }
func keyBlock() *pem.Block   { return &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("fake-key")} }
func ecKeyBlock() *pem.Block { return &pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("fake-ec-key")} }

// TestParseForwardExamples exercises every plain forwarding example from
// SKILL.md's summary table.
func TestParseForwardExamples(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantTarget Endpoint
		wantListen Endpoint
	}{
		{
			name:       "all interfaces, explicit listen host",
			args:       []string{"192.168.0.2:7777", "0.0.0.0:8888"},
			wantTarget: Endpoint{Addr: "192.168.0.2:7777", TCP: true},
			wantListen: Endpoint{Addr: "0.0.0.0:8888", TCP: true},
		},
		{
			name:       "loopback listen",
			args:       []string{"192.168.0.2:7777", "127.0.0.1:8888"},
			wantTarget: Endpoint{Addr: "192.168.0.2:7777", TCP: true},
			wantListen: Endpoint{Addr: "127.0.0.1:8888", TCP: true},
		},
		{
			name:       "bare port listen defaults to 0.0.0.0",
			args:       []string{"192.168.0.2:7777", "8888"},
			wantTarget: Endpoint{Addr: "192.168.0.2:7777", TCP: true},
			wantListen: Endpoint{Addr: "0.0.0.0:8888", TCP: true},
		},
		{
			name:       "hostname target",
			args:       []string{"backend.internal:7777", "8888"},
			wantTarget: Endpoint{Addr: "backend.internal:7777", TCP: true},
			wantListen: Endpoint{Addr: "0.0.0.0:8888", TCP: true},
		},
		{
			name:       "IPv6 target",
			args:       []string{"[2001:db8::2]:7777", "8888"},
			wantTarget: Endpoint{Addr: "[2001:db8::2]:7777", TCP: true},
			wantListen: Endpoint{Addr: "0.0.0.0:8888", TCP: true},
		},
		{
			name:       "IPv6 dual-stack listen",
			args:       []string{"[2001:db8::2]:7777", "[::]:8888"},
			wantTarget: Endpoint{Addr: "[2001:db8::2]:7777", TCP: true},
			wantListen: Endpoint{Addr: "[::]:8888", TCP: true},
		},
		{
			name:       "explicit TCP",
			args:       []string{"192.168.0.2:7777/TCP", "8888"},
			wantTarget: Endpoint{Addr: "192.168.0.2:7777", TCP: true},
			wantListen: Endpoint{Addr: "0.0.0.0:8888", TCP: true},
		},
		{
			name:       "UDP only",
			args:       []string{"192.168.0.2:7777/UDP", "8888"},
			wantTarget: Endpoint{Addr: "192.168.0.2:7777", UDP: true},
			wantListen: Endpoint{Addr: "0.0.0.0:8888", UDP: true},
		},
		{
			name:       "TCP+UDP",
			args:       []string{"192.168.0.2:7777/TCP/UDP", "8888"},
			wantTarget: Endpoint{Addr: "192.168.0.2:7777", TCP: true, UDP: true},
			wantListen: Endpoint{Addr: "0.0.0.0:8888", TCP: true, UDP: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Parse(tt.args)
			if err != nil {
				t.Fatalf("Parse(%v) error = %v", tt.args, err)
			}
			if cfg.Mode != ModeForward {
				t.Fatalf("Mode = %v, want ModeForward", cfg.Mode)
			}
			if cfg.Target != tt.wantTarget {
				t.Errorf("Target = %+v, want %+v", cfg.Target, tt.wantTarget)
			}
			if cfg.Listen != tt.wantListen {
				t.Errorf("Listen = %+v, want %+v", cfg.Listen, tt.wantListen)
			}
		})
	}
}

func TestParseTLS(t *testing.T) {
	dir := t.TempDir()
	certWithKey := writePEM(t, dir, "with_key.pem", certBlock(), keyBlock())
	certNoKey := writePEM(t, dir, "no_key.pem", certBlock())
	keyOnly := writePEM(t, dir, "key_only.pem", keyBlock())

	t.Run("TLS termination, separate key and cert", func(t *testing.T) {
		cfg, err := Parse([]string{"-key=" + keyOnly, "-cert=" + certNoKey, "192.168.0.2:7777", "8888/SSL"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cfg.Listen.SSL || cfg.Target.SSL {
			t.Errorf("Listen.SSL=%v Target.SSL=%v, want listen-side SSL only", cfg.Listen.SSL, cfg.Target.SSL)
		}
		if !cfg.Listen.TCP {
			t.Errorf("expected default TCP protocol")
		}
	})

	t.Run("TLS termination, cert with embedded key", func(t *testing.T) {
		cfg, err := Parse([]string{"-cert=" + certWithKey, "192.168.0.2:7777", "8888/SSL"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.KeyPath != "" {
			t.Errorf("KeyPath = %q, want empty", cfg.KeyPath)
		}
	})

	t.Run("mTLS with -ca=", func(t *testing.T) {
		ca := writePEM(t, dir, "client_ca.pem", certBlock())
		cfg, err := Parse([]string{"-key=" + keyOnly, "-cert=" + certNoKey, "-ca=" + ca, "192.168.0.2:7777", "8888/SSL"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.CAPath != ca {
			t.Errorf("CAPath = %q, want %q", cfg.CAPath, ca)
		}
	})

	t.Run("UDP-only DTLS termination requires -cert=", func(t *testing.T) {
		if _, err := Parse([]string{"192.168.0.2:7777/UDP/SSL", "8888"}); err == nil {
			t.Fatal("expected error: DTLS termination on UDP requires -cert=")
		}
	})

	t.Run("UDP-only DTLS termination with -cert= is valid", func(t *testing.T) {
		cfg, err := Parse([]string{"-key=" + keyOnly, "-cert=" + certNoKey, "192.168.0.2:7777/UDP/SSL", "8888"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cfg.Target.UDP || !cfg.Target.SSL || cfg.Target.TCP {
			t.Errorf("Target = %+v, want UDP+SSL only", cfg.Target)
		}
	})

	t.Run("TCP/UDP dual: TLS on TCP and DTLS on UDP, same cert", func(t *testing.T) {
		cfg, err := Parse([]string{"-key=" + keyOnly, "-cert=" + certNoKey, "192.168.0.2:7777", "8888/TCP/UDP/SSL"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cfg.Listen.TCP || !cfg.Listen.UDP || !cfg.Listen.SSL {
			t.Errorf("Listen = %+v, want TCP+UDP+SSL", cfg.Listen)
		}
		if cfg.Target.SSL {
			t.Errorf("Target.SSL = true, want false (target is plaintext)")
		}
	})

	t.Run("TLS origination toward target", func(t *testing.T) {
		cfg, err := Parse([]string{"192.168.0.2:7777/SSL", "8888"})
		// No -cert= given: cert is required whenever /SSL takes effect.
		if err == nil {
			t.Fatalf("Parse(%v) = %+v, want error (-cert= required)", []string{"192.168.0.2:7777/SSL", "8888"}, cfg)
		}
	})

	t.Run("TLS origination toward target with client cert", func(t *testing.T) {
		cfg, err := Parse([]string{"-key=" + keyOnly, "-cert=" + certNoKey, "-ca=" + certNoKey, "192.168.0.2:7777/SSL", "8888"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cfg.Target.SSL || cfg.Listen.SSL {
			t.Errorf("Target.SSL=%v Listen.SSL=%v, want target-side SSL only", cfg.Target.SSL, cfg.Listen.SSL)
		}
	})

	t.Run("lowercase and mixed-case-between-tokens suffixes", func(t *testing.T) {
		cfg, err := Parse([]string{"-key=" + keyOnly, "-cert=" + certNoKey, "192.168.0.2:7777/tcp/udp/ssl", "8888"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cfg.Target.TCP || !cfg.Target.UDP || !cfg.Target.SSL {
			t.Errorf("Target = %+v, want TCP+UDP+SSL", cfg.Target)
		}

		cfg2, err := Parse([]string{"-key=" + keyOnly, "-cert=" + certNoKey, "192.168.0.2:7777/TCP/ssl", "8888"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cfg2.Target.TCP || !cfg2.Target.SSL || cfg2.Target.UDP {
			t.Errorf("Target = %+v, want TCP+SSL only", cfg2.Target)
		}
	})
}

func TestParseProxyModes(t *testing.T) {
	t.Run("HTTP proxy", func(t *testing.T) {
		cfg, err := Parse([]string{"proxy", "8888"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Mode != ModeHTTPProxy {
			t.Errorf("Mode = %v, want ModeHTTPProxy", cfg.Mode)
		}
		if cfg.Listen.Addr != "0.0.0.0:8888" {
			t.Errorf("Listen.Addr = %q, want 0.0.0.0:8888", cfg.Listen.Addr)
		}
	})

	t.Run("SOCKS proxy", func(t *testing.T) {
		cfg, err := Parse([]string{"socks", "8888"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Mode != ModeSOCKSProxy {
			t.Errorf("Mode = %v, want ModeSOCKSProxy", cfg.Mode)
		}
	})

	t.Run("uppercase keyword", func(t *testing.T) {
		cfg, err := Parse([]string{"PROXY", "8888"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Mode != ModeHTTPProxy {
			t.Errorf("Mode = %v, want ModeHTTPProxy", cfg.Mode)
		}
	})

	t.Run("hostname literally named proxy with port is not proxy mode", func(t *testing.T) {
		cfg, err := Parse([]string{"proxy:7777", "8888"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Mode != ModeForward {
			t.Errorf("Mode = %v, want ModeForward", cfg.Mode)
		}
		if cfg.Target.Addr != "proxy:7777" {
			t.Errorf("Target.Addr = %q, want proxy:7777", cfg.Target.Addr)
		}
	})

	t.Run("mixed case does not trigger proxy mode and errors as bad host", func(t *testing.T) {
		if _, err := Parse([]string{"Proxy", "8888"}); err == nil {
			t.Fatal("expected error for mixed-case 'Proxy' (not a valid host:port either)")
		}
	})

	t.Run("proxy with -cert= is an error", func(t *testing.T) {
		if _, err := Parse([]string{"-cert=/x.pem", "proxy", "8888"}); err == nil {
			t.Fatal("expected error combining proxy mode with -cert=")
		}
	})

	t.Run("proxy with protocol suffix is an error", func(t *testing.T) {
		if _, err := Parse([]string{"proxy/TCP", "8888"}); err == nil {
			t.Fatal("expected error: 'proxy/TCP' is not proxy mode and has no port")
		}
	})

	t.Run("proxy with suffix on listen is an error", func(t *testing.T) {
		if _, err := Parse([]string{"proxy", "8888/TCP"}); err == nil {
			t.Fatal("expected error combining proxy mode with listen suffix")
		}
	})
}

func TestParseErrors(t *testing.T) {
	dir := t.TempDir()
	certNoKey := writePEM(t, dir, "no_key.pem", certBlock())
	keyOnly := writePEM(t, dir, "key_only.pem", keyBlock())

	tests := []struct {
		name string
		args []string
	}{
		{"wrong arg count", []string{"192.168.0.2:7777"}},
		{"too many args", []string{"192.168.0.2:7777", "8888", "extra"}},
		{"target missing port", []string{"192.168.0.2", "8888"}},
		{"target missing port, hostname", []string{"backend.internal", "8888"}},
		{"key without cert", []string{"-key=" + keyOnly, "192.168.0.2:7777", "8888"}},
		{"cert without key and without embedded key", []string{"-cert=" + certNoKey, "192.168.0.2:7777", "8888"}},
		{"SSL without cert", []string{"192.168.0.2:7777", "8888/SSL"}},
		{"mixed case suffix", []string{"192.168.0.2:7777/Tcp", "8888"}},
		{"unknown suffix", []string{"192.168.0.2:7777/FOO", "8888"}},
		{"wrong suffix order", []string{"192.168.0.2:7777/UDP/TCP", "8888"}},
		{"duplicate suffix", []string{"192.168.0.2:7777/TCP/TCP", "8888"}},
		{"port out of range", []string{"192.168.0.2:70000", "8888"}},
		{"port zero", []string{"192.168.0.2:0", "8888"}},
		{"invalid port", []string{"192.168.0.2:abc", "8888"}},
		{"bare hostname listen without port", []string{"192.168.0.2:7777", "example.com"}},
		{"duplicate cert option", []string{"-cert=a.pem", "-cert=b.pem", "192.168.0.2:7777", "8888"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse(tt.args); err == nil {
				t.Fatalf("Parse(%v) succeeded, want error", tt.args)
			}
		})
	}
}

func TestOptionOrderIndependence(t *testing.T) {
	dir := t.TempDir()
	certNoKey := writePEM(t, dir, "no_key.pem", certBlock())
	keyOnly := writePEM(t, dir, "key_only.pem", keyBlock())
	ca := writePEM(t, dir, "ca.pem", certBlock())

	orders := [][]string{
		{"-cert=" + certNoKey, "-key=" + keyOnly, "-ca=" + ca},
		{"-key=" + keyOnly, "-ca=" + ca, "-cert=" + certNoKey},
		{"-ca=" + ca, "-cert=" + certNoKey, "-key=" + keyOnly},
	}
	for _, opts := range orders {
		args := append(append([]string{}, opts...), "192.168.0.2:7777", "8888/SSL")
		cfg, err := Parse(args)
		if err != nil {
			t.Fatalf("Parse(%v) error = %v", args, err)
		}
		if cfg.KeyPath != keyOnly || cfg.CertPath != certNoKey || cfg.CAPath != ca {
			t.Errorf("Parse(%v) = key=%q cert=%q ca=%q", args, cfg.KeyPath, cfg.CertPath, cfg.CAPath)
		}
	}
}

func TestECPrivateKeyDetected(t *testing.T) {
	dir := t.TempDir()
	certWithECKey := writePEM(t, dir, "ec.pem", certBlock(), ecKeyBlock())
	cfg, err := Parse([]string{"-cert=" + certWithECKey, "192.168.0.2:7777", "8888/SSL"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.KeyPath != "" {
		t.Errorf("KeyPath = %q, want empty (EC PRIVATE KEY should be detected as embedded)", cfg.KeyPath)
	}
}

func TestParseVerify(t *testing.T) {
	t.Run("verify defaults to true", func(t *testing.T) {
		cfg, err := Parse([]string{"192.168.0.2:7777", "8888"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cfg.Verify {
			t.Errorf("Verify = false, want true when -verify= is omitted")
		}
	})

	t.Run("-verify=0 disables verification", func(t *testing.T) {
		cfg, err := Parse([]string{"-verify=0", "192.168.0.2:7777", "8888"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Verify {
			t.Errorf("Verify = true, want false when -verify=0 is given")
		}
	})

	t.Run("-verify=0 combines with other options in any order", func(t *testing.T) {
		dir := t.TempDir()
		certWithKey := writePEM(t, dir, "with_key.pem", certBlock(), keyBlock())
		cfg, err := Parse([]string{"-verify=0", "-cert=" + certWithKey, "192.168.0.2:7777/SSL", "8888"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Verify {
			t.Errorf("Verify = true, want false")
		}
	})
}

func TestParseLogLevelAndVerbose(t *testing.T) {
	t.Run("no -d/-v defaults to level 0, not verbose", func(t *testing.T) {
		cfg, err := Parse([]string{"192.168.0.2:7777", "8888"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.LogLevel != 0 || cfg.Verbose {
			t.Errorf("LogLevel/Verbose = %d/%v, want 0/false", cfg.LogLevel, cfg.Verbose)
		}
	})

	for _, tt := range []struct {
		tok  string
		want int
	}{
		{"-d", 1},
		{"-dd", 2},
		{"-ddd", 3},
	} {
		t.Run(tt.tok+" sets LogLevel", func(t *testing.T) {
			cfg, err := Parse([]string{tt.tok, "192.168.0.2:7777", "8888"})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.LogLevel != tt.want {
				t.Errorf("LogLevel = %d, want %d", cfg.LogLevel, tt.want)
			}
		})
	}

	t.Run("repeated/combined -d tokens take the highest level", func(t *testing.T) {
		cfg, err := Parse([]string{"-d", "-ddd", "192.168.0.2:7777", "8888"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.LogLevel != 3 {
			t.Errorf("LogLevel = %d, want 3", cfg.LogLevel)
		}
	})

	t.Run("-v sets Verbose independent of -d", func(t *testing.T) {
		cfg, err := Parse([]string{"-v", "192.168.0.2:7777", "8888"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cfg.Verbose || cfg.LogLevel != 0 {
			t.Errorf("Verbose/LogLevel = %v/%d, want true/0", cfg.Verbose, cfg.LogLevel)
		}
	})

	t.Run("-d and -v combine, any order", func(t *testing.T) {
		cfg, err := Parse([]string{"-v", "-dd", "192.168.0.2:7777", "8888"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cfg.Verbose || cfg.LogLevel != 2 {
			t.Errorf("Verbose/LogLevel = %v/%d, want true/2", cfg.Verbose, cfg.LogLevel)
		}
	})

	t.Run("-d/-v allowed with proxy mode", func(t *testing.T) {
		cfg, err := Parse([]string{"-ddd", "-v", "proxy", "8888"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Mode != ModeHTTPProxy || cfg.LogLevel != 3 || !cfg.Verbose {
			t.Errorf("cfg = %+v, want ModeHTTPProxy/level=3/verbose=true", cfg)
		}
	})
}

func TestParseVersion(t *testing.T) {
	t.Run("-version alone", func(t *testing.T) {
		cfg, err := Parse([]string{"-version"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Mode != ModeVersion {
			t.Errorf("Mode = %v, want ModeVersion", cfg.Mode)
		}
	})

	t.Run("-version takes precedence over other options and missing positional args", func(t *testing.T) {
		cfg, err := Parse([]string{"-cert=/x.pem", "-version"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Mode != ModeVersion {
			t.Errorf("Mode = %v, want ModeVersion", cfg.Mode)
		}
	})
}

func TestParseHelp(t *testing.T) {
	t.Run("-help alone", func(t *testing.T) {
		cfg, err := Parse([]string{"-help"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Mode != ModeHelp {
			t.Errorf("Mode = %v, want ModeHelp", cfg.Mode)
		}
	})

	t.Run("-help takes precedence over other options and missing positional args", func(t *testing.T) {
		cfg, err := Parse([]string{"-cert=/x.pem", "-help"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Mode != ModeHelp {
			t.Errorf("Mode = %v, want ModeHelp", cfg.Mode)
		}
	})

	t.Run("-help takes precedence over -version", func(t *testing.T) {
		cfg, err := Parse([]string{"-version", "-help"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.Mode != ModeHelp {
			t.Errorf("Mode = %v, want ModeHelp", cfg.Mode)
		}
	})
}

func TestParseAllSingleGroup(t *testing.T) {
	// With no "--" present, ParseAll must behave exactly like Parse: one
	// Config back, including ModeHelp/ModeVersion.
	cfgs, err := ParseAll([]string{"192.0.2.11:7777", "8888"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfgs) != 1 {
		t.Fatalf("len(cfgs) = %d, want 1", len(cfgs))
	}
	if cfgs[0].Target.Addr != "192.0.2.11:7777" || cfgs[0].Listen.Addr != "0.0.0.0:8888" {
		t.Errorf("cfgs[0] = %+v, unexpected", cfgs[0])
	}

	cfgs, err = ParseAll([]string{"-version"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfgs) != 1 || cfgs[0].Mode != ModeVersion {
		t.Fatalf("ParseAll([-version]) = %+v, want single ModeVersion Config", cfgs)
	}
}

func TestParseAllMultiGroup(t *testing.T) {
	t.Run("two valid groups", func(t *testing.T) {
		cfgs, err := ParseAll([]string{"192.0.2.11:7777", "8888", "--", "192.0.2.11:5555", "6666"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cfgs) != 2 {
			t.Fatalf("len(cfgs) = %d, want 2", len(cfgs))
		}
		if cfgs[0].Target.Addr != "192.0.2.11:7777" || cfgs[0].Listen.Addr != "0.0.0.0:8888" {
			t.Errorf("cfgs[0] = %+v, unexpected", cfgs[0])
		}
		if cfgs[1].Target.Addr != "192.0.2.11:5555" || cfgs[1].Listen.Addr != "0.0.0.0:6666" {
			t.Errorf("cfgs[1] = %+v, unexpected", cfgs[1])
		}
	})

	t.Run("three valid groups, mixing forward and proxy", func(t *testing.T) {
		cfgs, err := ParseAll([]string{
			"192.0.2.11:7777", "8888",
			"--", "proxy", "9999",
			"--", "socks", "1080",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cfgs) != 3 {
			t.Fatalf("len(cfgs) = %d, want 3", len(cfgs))
		}
		if cfgs[1].Mode != ModeHTTPProxy || cfgs[2].Mode != ModeSOCKSProxy {
			t.Errorf("cfgs[1].Mode=%v cfgs[2].Mode=%v, want HTTPProxy/SOCKSProxy", cfgs[1].Mode, cfgs[2].Mode)
		}
	})

	t.Run("one invalid group fails the whole thing, nothing partially runs", func(t *testing.T) {
		cfgs, err := ParseAll([]string{"192.0.2.11:7777", "8888", "--", "192.0.2.11", "6666"})
		if err == nil {
			t.Fatal("expected error when one of several groups is invalid")
		}
		if cfgs != nil {
			t.Errorf("cfgs = %+v, want nil on error", cfgs)
		}
	})

	t.Run("all groups invalid reports all errors", func(t *testing.T) {
		_, err := ParseAll([]string{"bad1", "--", "bad2"})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("-help combined with -- is an error", func(t *testing.T) {
		if _, err := ParseAll([]string{"-help", "--", "192.0.2.11:7777", "8888"}); err == nil {
			t.Fatal("expected error combining -help with --")
		}
	})

	t.Run("-version combined with -- is an error", func(t *testing.T) {
		if _, err := ParseAll([]string{"192.0.2.11:7777", "8888", "--", "-version"}); err == nil {
			t.Fatal("expected error combining -version with --")
		}
	})

	t.Run("empty group from leading -- is an error", func(t *testing.T) {
		if _, err := ParseAll([]string{"--", "192.0.2.11:7777", "8888"}); err == nil {
			t.Fatal("expected error for empty leading group")
		}
	})
}

func TestParseSignCA(t *testing.T) {
	t.Run("-signca= alone with listen-side SSL is valid", func(t *testing.T) {
		cfg, err := Parse([]string{"-signca=/ca.pem", "192.0.2.11:7777", "8888/SSL"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.SignCAPath != "/ca.pem" {
			t.Errorf("SignCAPath = %q, want /ca.pem", cfg.SignCAPath)
		}
		if cfg.CertPath != "" || cfg.KeyPath != "" {
			t.Errorf("CertPath=%q KeyPath=%q, want both empty", cfg.CertPath, cfg.KeyPath)
		}
	})

	t.Run("-signca= with -cert= is an error", func(t *testing.T) {
		if _, err := Parse([]string{"-signca=/ca.pem", "-cert=/x.pem", "192.0.2.11:7777", "8888/SSL"}); err == nil {
			t.Fatal("expected error combining -signca= with -cert=")
		}
	})

	t.Run("-signca= with -key= is an error", func(t *testing.T) {
		if _, err := Parse([]string{"-signca=/ca.pem", "-key=/x.key", "192.0.2.11:7777", "8888/SSL"}); err == nil {
			t.Fatal("expected error combining -signca= with -key=")
		}
	})

	t.Run("-signca= without listen-side SSL is an error", func(t *testing.T) {
		if _, err := Parse([]string{"-signca=/ca.pem", "192.0.2.11:7777", "8888"}); err == nil {
			t.Fatal("expected error: -signca= requires /SSL on the listen side")
		}
	})

	t.Run("-signca= with SSL only on target side is an error", func(t *testing.T) {
		if _, err := Parse([]string{"-signca=/ca.pem", "192.0.2.11:7777/SSL", "8888"}); err == nil {
			t.Fatal("expected error: -signca= requires listen-side SSL, not target-side")
		}
	})

	t.Run("-signca= with SSL on both target and listen is an error", func(t *testing.T) {
		if _, err := Parse([]string{"-signca=/ca.pem", "192.0.2.11:7777/SSL", "8888/SSL"}); err == nil {
			t.Fatal("expected error: -signca= cannot combine with target-side TLS origination")
		}
	})

	t.Run("-signca= with listen-side UDP+SSL (DTLS) is an error", func(t *testing.T) {
		if _, err := Parse([]string{"-signca=/ca.pem", "192.0.2.11:7777/UDP", "8888/TCP/UDP/SSL"}); err == nil {
			t.Fatal("expected error: -signca= does not support DTLS termination over UDP")
		}
	})

	t.Run("-signca= combined with -ca= for mTLS client verification is valid", func(t *testing.T) {
		cfg, err := Parse([]string{"-signca=/ca.pem", "-ca=/client-ca.pem", "192.0.2.11:7777", "8888/SSL"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.CAPath != "/client-ca.pem" {
			t.Errorf("CAPath = %q, want /client-ca.pem", cfg.CAPath)
		}
	})

	t.Run("duplicate -signca= is an error", func(t *testing.T) {
		if _, err := Parse([]string{"-signca=/a.pem", "-signca=/b.pem", "192.0.2.11:7777", "8888/SSL"}); err == nil {
			t.Fatal("expected error for duplicate -signca=")
		}
	})

	t.Run("-signca= combined with proxy mode is an error", func(t *testing.T) {
		if _, err := Parse([]string{"-signca=/ca.pem", "proxy", "8888"}); err == nil {
			t.Fatal("expected error combining proxy mode with -signca=")
		}
	})
}

func TestParseServerName(t *testing.T) {
	t.Run("-servername= without -signca= is an error", func(t *testing.T) {
		if _, err := Parse([]string{"-servername=example.com", "192.0.2.11:7777", "8888/SSL"}); err == nil {
			t.Fatal("expected error: -servername= requires -signca=")
		}
	})

	t.Run("-servername= with -signca= is valid", func(t *testing.T) {
		cfg, err := Parse([]string{"-signca=/ca.pem", "-servername=example.com", "192.0.2.11:7777", "8888/SSL"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.ServerName != "example.com" {
			t.Errorf("ServerName = %q, want example.com", cfg.ServerName)
		}
	})

	t.Run("duplicate -servername= is an error", func(t *testing.T) {
		if _, err := Parse([]string{"-signca=/ca.pem", "-servername=a.com", "-servername=b.com", "192.0.2.11:7777", "8888/SSL"}); err == nil {
			t.Fatal("expected error for duplicate -servername=")
		}
	})

	t.Run("-servername= combined with proxy mode is an error", func(t *testing.T) {
		if _, err := Parse([]string{"-servername=example.com", "proxy", "8888"}); err == nil {
			t.Fatal("expected error combining proxy mode with -servername=")
		}
	})
}
