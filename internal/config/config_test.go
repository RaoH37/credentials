package config

import (
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckLoopback(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1:12345": true,
		"127.0.0.2:80":    true,
		"[::1]:8080":      true,
		"localhost:1":     true,
		"0.0.0.0:12345":   false,
		":12345":          false,
		"[::]:12345":      false,
		"192.168.1.2:80":  false,
		"example.com:80":  false,
		"127.0.0.1":       false,
		"127.0.0.1:":      false,
	} {
		if err := CheckLoopback(addr); (err == nil) != ok {
			t.Errorf("CheckLoopback(%q) = %v, want ok=%v", addr, err, ok)
		}
	}
}

func parse(t *testing.T, args ...string) (Config, error) {
	t.Helper()
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	resolve := Flags(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return resolve()
}

func TestPrecedence(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dir)

	cfg, err := parse(t)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != DefaultAddr || cfg.DB != filepath.Join(dir, "credentials", "credentials.db") {
		t.Fatalf("defaults: %+v", cfg)
	}

	file := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(file, []byte("addr = \"127.0.0.1:2000\"\ndb = \"/tmp/file.db\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = parse(t, "-config", file)
	if err != nil || cfg.Addr != "127.0.0.1:2000" || cfg.DB != "/tmp/file.db" {
		t.Fatalf("file: %v %+v", err, cfg)
	}

	cfg, err = parse(t, "-config", file, "-addr", "127.0.0.1:3000", "-db", "/tmp/flag.db")
	if err != nil || cfg.Addr != "127.0.0.1:3000" || cfg.DB != "/tmp/flag.db" {
		t.Fatalf("flags: %v %+v", err, cfg)
	}
}

func TestConfigErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	tests := map[string][]string{
		"unknown key":     {"-config", write("typo.toml", `adr = "127.0.0.1:1"`)},
		"invalid toml":    {"-config", write("bad.toml", `addr = `)},
		"missing file":    {"-config", filepath.Join(dir, "missing.toml")},
		"non loopback":    {"-addr", "0.0.0.0:12345"},
		"file not loopbk": {"-config", write("open.toml", `addr = "0.0.0.0:1"`)},
	}
	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parse(t, args...); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestDefaultDBPathIgnoresRelativeXDG(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "relative/dir")
	p, err := DefaultDBPath()
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(p, "relative") {
		t.Fatalf("relative XDG_DATA_HOME must be ignored, got %q", p)
	}
}
