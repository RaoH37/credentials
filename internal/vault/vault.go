// Package vault provides the cryptographic primitives used to protect stored
// credentials: Argon2id key derivation and AES-256-GCM authenticated
// encryption.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	// KeyLen is the size of the derived key (AES-256).
	KeyLen = 32
	// SaltLen is the size of the random salt fed to Argon2id.
	SaltLen = 16
)

// ErrDecrypt is returned when a ciphertext cannot be authenticated: wrong key,
// wrong associated data, or tampered data.
var ErrDecrypt = errors.New("vault: decryption failed")

// KDFParams are the Argon2id cost parameters.
type KDFParams struct {
	Time    uint32 // number of passes
	Memory  uint32 // memory in KiB
	Threads uint8
}

// DefaultKDFParams follow the OWASP recommendations for Argon2id.
var DefaultKDFParams = KDFParams{Time: 3, Memory: 64 * 1024, Threads: 4}

// Validate rejects parameters that are too weak or absurdly expensive, so a
// tampered database cannot downgrade the KDF or exhaust memory.
func (p KDFParams) Validate() error {
	switch {
	case p.Time < 1 || p.Time > 100:
		return fmt.Errorf("vault: argon2 time %d out of range [1,100]", p.Time)
	case p.Memory < 8*1024 || p.Memory > 4*1024*1024:
		return fmt.Errorf("vault: argon2 memory %d KiB out of range [8 MiB,4 GiB]", p.Memory)
	case p.Threads < 1:
		return fmt.Errorf("vault: argon2 threads must be >= 1")
	}
	return nil
}

// String encodes the parameters in the PHC-like format stored in the database.
func (p KDFParams) String() string {
	return fmt.Sprintf("argon2id$v=%d$m=%d,t=%d,p=%d", argon2.Version, p.Memory, p.Time, p.Threads)
}

// ParseKDFParams decodes the output of KDFParams.String.
func ParseKDFParams(s string) (KDFParams, error) {
	var p KDFParams
	var v int
	if _, err := fmt.Sscanf(s, "argon2id$v=%d$m=%d,t=%d,p=%d", &v, &p.Memory, &p.Time, &p.Threads); err != nil {
		return p, fmt.Errorf("vault: invalid kdf parameters %q: %w", s, err)
	}
	if v != argon2.Version {
		return p, fmt.Errorf("vault: unsupported argon2 version %d", v)
	}
	return p, p.Validate()
}

// NewSalt returns a random salt suitable for DeriveKey.
func NewSalt() ([]byte, error) {
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("vault: generate salt: %w", err)
	}
	return salt, nil
}

// DeriveKey derives a KeyLen-byte key from a passphrase with Argon2id.
func DeriveKey(passphrase []byte, salt []byte, p KDFParams) []byte {
	return argon2.IDKey(passphrase, salt, p.Time, p.Memory, p.Threads, KeyLen)
}

// Cipher encrypts and decrypts data with AES-256-GCM. It is safe for
// concurrent use.
type Cipher struct {
	aead cipher.AEAD
}

// NewCipher returns a Cipher for a KeyLen-byte key.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != KeyLen {
		return nil, fmt.Errorf("vault: key must be %d bytes, got %d", KeyLen, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// Encrypt returns nonce || ciphertext. The associated data binds the
// ciphertext to its context (e.g. a row id) so it cannot be moved elsewhere.
func (c *Cipher) Encrypt(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize(), c.aead.NonceSize()+len(plaintext)+c.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("vault: generate nonce: %w", err)
	}
	return c.aead.Seal(nonce, nonce, plaintext, aad), nil
}

// Decrypt reverses Encrypt. It returns ErrDecrypt if authentication fails.
func (c *Cipher) Decrypt(data, aad []byte) ([]byte, error) {
	ns := c.aead.NonceSize()
	if len(data) < ns+c.aead.Overhead() {
		return nil, ErrDecrypt
	}
	pt, err := c.aead.Open(nil, data[:ns], data[ns:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}
