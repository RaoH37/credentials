package vault

import (
	"bytes"
	"errors"
	"testing"
)

func newTestCipher(t *testing.T) *Cipher {
	t.Helper()
	c, err := NewCipher(bytes.Repeat([]byte{7}, KeyLen))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	c := newTestCipher(t)
	for _, pt := range [][]byte{nil, []byte("x"), bytes.Repeat([]byte("secret"), 10000)} {
		ct, err := c.Encrypt(pt, []byte("aad"))
		if err != nil {
			t.Fatal(err)
		}
		got, err := c.Decrypt(ct, []byte("aad"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, pt) {
			t.Fatalf("round trip mismatch for %d bytes", len(pt))
		}
	}
}

func TestEncryptUsesRandomNonce(t *testing.T) {
	c := newTestCipher(t)
	a, _ := c.Encrypt([]byte("same"), nil)
	b, _ := c.Encrypt([]byte("same"), nil)
	if bytes.Equal(a, b) {
		t.Fatal("two encryptions of the same plaintext are identical")
	}
}

func TestDecryptFailures(t *testing.T) {
	c := newTestCipher(t)
	ct, err := c.Encrypt([]byte("secret"), []byte("credential:1"))
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewCipher(bytes.Repeat([]byte{8}, KeyLen))
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(ct)
	tampered[len(tampered)-1] ^= 1

	tests := []struct {
		name string
		c    *Cipher
		data []byte
		aad  string
	}{
		{"wrong aad", c, ct, "credential:2"},
		{"wrong key", other, ct, "credential:1"},
		{"tampered", c, tampered, "credential:1"},
		{"truncated", c, ct[:10], "credential:1"},
		{"empty", c, nil, "credential:1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.c.Decrypt(tt.data, []byte(tt.aad)); !errors.Is(err, ErrDecrypt) {
				t.Fatalf("got %v, want ErrDecrypt", err)
			}
		})
	}
}

func TestNewCipherRejectsBadKeyLength(t *testing.T) {
	if _, err := NewCipher(make([]byte, 16)); err == nil {
		t.Fatal("expected an error for a 16-byte key")
	}
}

func TestKDFParamsRoundTrip(t *testing.T) {
	s := DefaultKDFParams.String()
	got, err := ParseKDFParams(s)
	if err != nil {
		t.Fatal(err)
	}
	if got != DefaultKDFParams {
		t.Fatalf("got %+v, want %+v", got, DefaultKDFParams)
	}
}

func TestParseKDFParamsRejectsWeakOrInvalid(t *testing.T) {
	for _, s := range []string{
		"",
		"argon2id$v=19$m=1024,t=3,p=4",     // memory too low
		"argon2id$v=19$m=65536,t=0,p=4",    // time too low
		"argon2id$v=19$m=65536,t=3,p=0",    // no threads
		"argon2id$v=16$m=65536,t=3,p=4",    // unsupported version
		"argon2i$v=19$m=65536,t=3,p=4",     // wrong algorithm
		"argon2id$v=19$m=99999999,t=3,p=4", // memory too high
	} {
		if _, err := ParseKDFParams(s); err == nil {
			t.Errorf("ParseKDFParams(%q): expected an error", s)
		}
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	p := KDFParams{Time: 1, Memory: 8 * 1024, Threads: 1}
	salt := []byte("0123456789abcdef")
	a := DeriveKey([]byte("pass"), salt, p)
	b := DeriveKey([]byte("pass"), salt, p)
	c := DeriveKey([]byte("pass"), []byte("fedcba9876543210"), p)
	if !bytes.Equal(a, b) || bytes.Equal(a, c) || len(a) != KeyLen {
		t.Fatal("DeriveKey is not deterministic per (passphrase, salt)")
	}
}
