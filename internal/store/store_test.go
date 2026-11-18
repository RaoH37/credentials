package store

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RaoH37/credentials/internal/vault"
)

// fastKDF keeps tests fast; production uses vault.DefaultKDFParams.
var fastKDF = WithKDFParams(vault.KDFParams{Time: 1, Memory: 8 * 1024, Threads: 1})

const testPass = "correct horse battery staple"

func openTest(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(context.Background(), path, []byte(testPass), fastKDF)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	return openTest(t, path), path
}

func TestCRUD(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)

	c := &Credential{Name: "  svc  ", Description: "desc", Format: "JSON", Content: `{"u":"a"}`}
	if err := s.Create(ctx, c); err != nil {
		t.Fatal(err)
	}
	if c.ID == 0 || c.Name != "svc" || c.Format != FormatJSON {
		t.Fatalf("unexpected normalized credential: %+v", c)
	}

	got, err := s.Get(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Content != `{"u":"a"}` || got.Description != "desc" {
		t.Fatalf("Get returned %+v", got)
	}
	byName, err := s.GetByName(ctx, "svc")
	if err != nil || byName.ID != c.ID {
		t.Fatalf("GetByName: %v, %+v", err, byName)
	}

	list, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Content != "" {
		t.Fatalf("List must not return content: %+v", list)
	}

	got.Content = "changed"
	got.Format = FormatTXT
	if err := s.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Get(ctx, c.ID); got.Content != "changed" {
		t.Fatalf("update not applied: %+v", got)
	}

	if err := s.Delete(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, c.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after delete: %v", err)
	}
	if err := s.Delete(ctx, c.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second Delete: %v", err)
	}
	if err := s.Update(ctx, &Credential{ID: 999, Name: "x"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Update missing: %v", err)
	}
}

func TestValidation(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	if err := s.Create(ctx, &Credential{Name: "dup", Content: "a"}); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		c    Credential
	}{
		{"empty name", Credential{Name: "  "}},
		{"slash in name", Credential{Name: "a/b"}},
		{"control char", Credential{Name: "a\nb"}},
		{"long name", Credential{Name: strings.Repeat("a", MaxNameLen+1)}},
		{"long description", Credential{Name: "x", Description: strings.Repeat("a", MaxDescriptionLen+1)}},
		{"content too large", Credential{Name: "x", Content: strings.Repeat("a", MaxContentSize+1)}},
		{"invalid utf8", Credential{Name: "x", Content: "\xff"}},
		{"unknown format", Credential{Name: "x", Format: "xml"}},
		{"bad json", Credential{Name: "x", Format: FormatJSON, Content: "{"}},
		{"bad yaml", Credential{Name: "x", Format: FormatYAML, Content: "a: [b"}},
		{"bad toml", Credential{Name: "x", Format: FormatTOML, Content: "a ="}},
		{"bad pem", Credential{Name: "x", Format: FormatPEM, Content: "not pem"}},
		{"duplicate name", Credential{Name: "dup"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.c
			var ve *ValidationError
			if err := s.Create(ctx, &c); !errors.As(err, &ve) {
				t.Fatalf("got %v, want *ValidationError", err)
			}
		})
	}
}

func TestWrongPassphrase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s := openTest(t, path)
	s.Close()
	if _, err := Open(context.Background(), path, []byte("wrong"), fastKDF); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("got %v, want ErrWrongPassphrase", err)
	}
}

func TestExclusiveLock(t *testing.T) {
	_, path := newTestStore(t)
	if _, err := Open(context.Background(), path, []byte(testPass), fastKDF); !errors.Is(err, ErrLocked) {
		t.Fatalf("got %v, want ErrLocked", err)
	}
}

func TestPersistenceAndPermissions(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "test.db")
	s := openTest(t, path)
	if err := s.Create(ctx, &Credential{Name: "svc", Content: "secret-value"}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("database permissions %o, want owner-only", perm)
	}
	raw := readAll(t, path)
	if strings.Contains(raw, "secret-value") {
		t.Error("plaintext secret found in the database file")
	}

	s = openTest(t, path)
	if c, err := s.GetByName(ctx, "svc"); err != nil || c.Content != "secret-value" {
		t.Fatalf("after reopen: %v, %+v", err, c)
	}
}

// TestCiphertextBoundToRow checks that swapping ciphertexts between rows in
// the database is detected instead of returning another row's secret.
func TestCiphertextBoundToRow(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	a := &Credential{Name: "a", Content: "secret-a"}
	b := &Credential{Name: "b", Content: "secret-b"}
	if err := s.Create(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := s.Create(ctx, b); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE credentials SET credentials = (SELECT credentials FROM credentials WHERE id = ?) WHERE id = ?`, a.ID, b.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, b.ID); !errors.Is(err, vault.ErrDecrypt) {
		t.Fatalf("got %v, want vault.ErrDecrypt", err)
	}
}

func TestRekey(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "test.db")
	s := openTest(t, path)
	for _, name := range []string{"a", "b", "c"} {
		if err := s.Create(ctx, &Credential{Name: name, Content: "secret-" + name}); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.Rekey(ctx, []byte("a brand new passphrase"), fastKDF)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("rekeyed %d credentials, want 3", n)
	}
	// The store keeps working with the new key.
	if c, err := s.GetByName(ctx, "b"); err != nil || c.Content != "secret-b" {
		t.Fatalf("after rekey: %v, %+v", err, c)
	}
	s.Close()

	if _, err := Open(ctx, path, []byte(testPass), fastKDF); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("old passphrase: got %v, want ErrWrongPassphrase", err)
	}
	s2, err := Open(ctx, path, []byte("a brand new passphrase"), fastKDF)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	for _, name := range []string{"a", "b", "c"} {
		if c, err := s2.GetByName(ctx, name); err != nil || c.Content != "secret-"+name {
			t.Fatalf("%s after reopen: %v, %+v", name, err, c)
		}
	}
	if _, err := os.Stat(path + "-wal"); err == nil {
		if fi, _ := os.Stat(path + "-wal"); fi.Size() != 0 {
			t.Errorf("WAL not truncated after rekey: %d bytes", fi.Size())
		}
	}
}

// TestLegacyDatabase opens a database created by the first version of the
// program (no "kdf" metadata) to guarantee backward compatibility.
func TestLegacyDatabase(t *testing.T) {
	ctx := context.Background()
	src := readAll(t, filepath.Join("testdata", "legacy.db"))
	path := filepath.Join(t.TempDir(), "legacy.db")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, path, []byte("legacy-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := s.GetByName(ctx, "legacy-service")
	if err != nil {
		t.Fatal(err)
	}
	if c.Content != `{"user":"alice","password":"s3cr3t"}` || c.Format != FormatJSON {
		t.Fatalf("unexpected legacy credential: %+v", c)
	}
	if _, err := s.Rekey(ctx, []byte("a modern passphrase"), fastKDF); err != nil {
		t.Fatal(err)
	}
	if c, err := s.GetByName(ctx, "legacy-token"); err != nil || c.Content != "tok-123" {
		t.Fatalf("after rekey: %v, %+v", err, c)
	}
}

func TestOpenRejectsBadInput(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if _, err := Open(ctx, filepath.Join(dir, "a.db"), nil, fastKDF); err == nil {
		t.Error("empty passphrase accepted")
	}
	if _, err := Open(ctx, filepath.Join(dir, "a?b.db"), []byte(testPass), fastKDF); err == nil {
		t.Error("path with '?' accepted")
	}
	weak := WithKDFParams(vault.KDFParams{Time: 1, Memory: 1, Threads: 1})
	if _, err := Open(ctx, filepath.Join(dir, "b.db"), []byte(testPass), weak); err == nil {
		t.Error("weak KDF parameters accepted")
	}
}

func readAll(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
