package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/term"
)

// MinPassphraseLen is the minimum length enforced for new passphrases.
// Existing databases keep working with shorter ones.
const MinPassphraseLen = 12

const (
	envPassphrase     = "CREDENTIALS_PASSPHRASE"
	envSystemdCredDir = "CREDENTIALS_DIRECTORY"
	systemdCredName   = "passphrase"
	maxPassphraseSize = 4096
)

var errNoPassphrase = errors.New("no passphrase available: no systemd credential, " + envPassphrase + " unset and stdin is not a terminal")

// readPassphrase returns the passphrase from, in order:
//  1. the systemd credential "passphrase" ($CREDENTIALS_DIRECTORY/passphrase),
//     decrypted by systemd when the service starts (LoadCredentialEncrypted);
//  2. the CREDENTIALS_PASSPHRASE environment variable, which is then removed
//     from the environment;
//  3. an interactive prompt, with confirmation when isNew is true.
func readPassphrase(isNew bool, stderr io.Writer) ([]byte, error) {
	p, err := passphraseFromSystemd()
	if err != nil || p != nil {
		return p, err
	}
	if v, ok := os.LookupEnv(envPassphrase); ok {
		_ = os.Unsetenv(envPassphrase) // do not leak it to child processes
		if v == "" {
			return nil, errors.New(envPassphrase + " is empty")
		}
		return []byte(v), nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errNoPassphrase
	}
	if !isNew {
		return prompt(stderr, "Passphrase: ")
	}
	fmt.Fprintln(stderr, "New database: this passphrase will encrypt every credential. It is not stored anywhere.")
	return promptNew(stderr, "Passphrase: ")
}

func passphraseFromSystemd() ([]byte, error) {
	dir := os.Getenv(envSystemdCredDir)
	if dir == "" {
		return nil, nil
	}
	b, err := os.ReadFile(filepath.Join(dir, systemdCredName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read systemd credential: %w", err)
	}
	b = bytes.TrimRight(b, "\r\n")
	if len(b) == 0 {
		return nil, errors.New("systemd credential " + systemdCredName + " is empty")
	}
	return b, nil
}

// prompt reads a line from the terminal without echo.
func prompt(stderr io.Writer, label string) ([]byte, error) {
	fmt.Fprint(stderr, label)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(stderr)
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	if len(b) == 0 {
		return nil, errors.New("empty passphrase")
	}
	return b, nil
}

// promptNew asks for a new passphrase twice and checks its strength.
func promptNew(stderr io.Writer, label string) ([]byte, error) {
	p, err := prompt(stderr, label)
	if err != nil {
		return nil, err
	}
	if err := checkNewPassphrase(p); err != nil {
		return nil, err
	}
	c, err := prompt(stderr, "Confirm: ")
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(p, c) {
		return nil, errors.New("passphrases do not match")
	}
	return p, nil
}

func checkNewPassphrase(p []byte) error {
	switch {
	case len(bytes.TrimSpace(p)) < MinPassphraseLen:
		return fmt.Errorf("passphrase must be at least %d characters", MinPassphraseLen)
	case len(p) > maxPassphraseSize:
		return fmt.Errorf("passphrase must be at most %d bytes", maxPassphraseSize)
	}
	return nil
}
