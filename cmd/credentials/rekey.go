package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"

	"github.com/RaoH37/credentials/internal/config"
	"github.com/RaoH37/credentials/internal/store"
)

// runRekey implements "credentials rekey": it re-encrypts the database with a
// new passphrase.
func runRekey(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("rekey", flag.ContinueOnError)
	fs.SetOutput(stderr)
	resolve := config.Flags(fs)
	fromStdin := fs.Bool("stdin", false, "read the current then the new passphrase from stdin, one per line")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "Usage: credentials rekey [options]\n\n"+
			"Re-encrypts every credential with a new passphrase.\n"+
			"The server must be stopped while the command runs.\n"+
			"With the .deb package, use instead: sudo credentials-passphrase --change\n\n"+
			"Options:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		fs.Usage()
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	cfg, err := resolve()
	if err != nil {
		return err
	}

	// store.Open would create an empty database: require an existing one.
	if _, err := os.Stat(cfg.DB); err != nil {
		return fmt.Errorf("database not found: %w", err)
	}

	oldPass, newPass, err := readRekeyPassphrases(*fromStdin, stderr)
	if err != nil {
		return err
	}
	defer clear(oldPass)
	defer clear(newPass)
	if err := checkNewPassphrase(newPass); err != nil {
		return err
	}
	if bytes.Equal(oldPass, newPass) {
		return errors.New("the new passphrase is identical to the current one")
	}

	// Open takes an exclusive lock: it fails if a server is using the
	// database, since a running server would keep writing with the old key.
	st, err := store.Open(ctx, cfg.DB, oldPass)
	switch {
	case errors.Is(err, store.ErrWrongPassphrase):
		return errors.New("current passphrase is incorrect")
	case errors.Is(err, store.ErrLocked):
		return fmt.Errorf("%s: %w: stop the server before changing the passphrase", cfg.DB, err)
	case err != nil:
		return err
	}
	defer st.Close()

	fmt.Fprintf(stderr, "Re-encrypting %s...\n", cfg.DB)
	n, err := st.Rekey(ctx, newPass)
	if err != nil {
		return fmt.Errorf("rekey aborted, the database is unchanged: %w", err)
	}
	fmt.Fprintf(stderr, "Passphrase changed: %d credential(s) re-encrypted.\n", n)
	return nil
}

func readRekeyPassphrases(fromStdin bool, stderr io.Writer) (oldPass, newPass []byte, err error) {
	if fromStdin {
		sc := bufio.NewScanner(io.LimitReader(os.Stdin, 2*maxPassphraseSize+4))
		var lines [][]byte
		for len(lines) < 2 && sc.Scan() {
			lines = append(lines, bytes.Clone(bytes.TrimRight(sc.Bytes(), "\r")))
		}
		if err := sc.Err(); err != nil {
			return nil, nil, fmt.Errorf("read stdin: %w", err)
		}
		if len(lines) < 2 || len(lines[0]) == 0 || len(lines[1]) == 0 {
			return nil, nil, errors.New("-stdin expects two non-empty lines: current then new passphrase")
		}
		return lines[0], lines[1], nil
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, nil, errors.New("stdin is not a terminal: use -stdin")
	}
	if oldPass, err = prompt(stderr, "Current passphrase: "); err != nil {
		return nil, nil, err
	}
	if newPass, err = promptNew(stderr, "New passphrase: "); err != nil {
		clear(oldPass)
		return nil, nil, err
	}
	return oldPass, newPass, nil
}
