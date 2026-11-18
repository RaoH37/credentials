package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestPassphraseFromSystemdCredential(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "passphrase"), []byte("from systemd\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envSystemdCredDir, dir)
	t.Setenv(envPassphrase, "from env")

	p, err := readPassphrase(false, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if string(p) != "from systemd" {
		t.Fatalf("got %q, want the systemd credential first", p)
	}
}

func TestPassphraseFromEnvIsUnset(t *testing.T) {
	t.Setenv(envSystemdCredDir, "")
	t.Setenv(envPassphrase, "from env")

	p, err := readPassphrase(false, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if string(p) != "from env" {
		t.Fatalf("got %q", p)
	}
	if _, ok := os.LookupEnv(envPassphrase); ok {
		t.Fatal(envPassphrase + " must be removed from the environment")
	}
}

func TestEmptySystemdCredentialIsAnError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "passphrase"), []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(envSystemdCredDir, dir)
	if _, err := readPassphrase(false, io.Discard); err == nil {
		t.Fatal("expected an error")
	}
}

func TestCheckNewPassphrase(t *testing.T) {
	for p, ok := range map[string]bool{
		"short":                      false,
		"            ":               false,
		"twelve chars":               true,
		"a long enough passphrase!!": true,
	} {
		if err := checkNewPassphrase([]byte(p)); (err == nil) != ok {
			t.Errorf("checkNewPassphrase(%q) = %v, want ok=%v", p, err, ok)
		}
	}
}
