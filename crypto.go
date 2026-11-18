package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Paramètres Argon2id (recommandations OWASP).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4
	keyLen       = 32 // AES-256
	saltLen      = 16
)

// verifierPlaintext est chiffré à l'initialisation de la base, puis déchiffré
// au démarrage pour vérifier que la passphrase fournie est la bonne.
const verifierPlaintext = "credentials-vault-ok"

var ErrBadPassphrase = errors.New("passphrase incorrecte")

type Cipher struct {
	aead cipher.AEAD
}

func deriveKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemory, argonThreads, keyLen)
}

func NewCipher(key []byte) (*Cipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead}, nil
}

// Encrypt renvoie nonce || ciphertext. aad lie le chiffré à son contexte
// (ex : l'id de la ligne) pour empêcher l'échange de valeurs entre lignes.
func (c *Cipher) Encrypt(plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return c.aead.Seal(nonce, nonce, plaintext, aad), nil
}

func (c *Cipher) Decrypt(data, aad []byte) ([]byte, error) {
	ns := c.aead.NonceSize()
	if len(data) < ns {
		return nil, fmt.Errorf("donnée chiffrée trop courte")
	}
	return c.aead.Open(nil, data[:ns], data[ns:], aad)
}
