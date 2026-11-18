package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

// runRekey implémente « credentials rekey » : rechiffre la base avec une
// nouvelle passphrase.
func runRekey(args []string) error {
	fs := flag.NewFlagSet("rekey", flag.ContinueOnError)
	resolve := commonFlags(fs)
	fromStdin := fs.Bool("stdin", false, "lit l'ancienne puis la nouvelle passphrase sur l'entrée standard (une par ligne)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage : credentials rekey [options]\n\n"+
			"Rechiffre tous les credentials avec une nouvelle passphrase.\n"+
			"Le serveur doit être arrêté pendant l'opération.\n"+
			"Avec le paquet .deb, utilisez plutôt : sudo credentials-passphrase --change\n\nOptions :\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	cfg, err := resolve()
	if err != nil {
		return err
	}

	// OpenStore créerait une base vide : on exige qu'elle existe.
	if _, err := os.Stat(cfg.DB); err != nil {
		return fmt.Errorf("base introuvable : %w", err)
	}
	// Un serveur en cours d'exécution garde l'ancienne clé en mémoire et
	// écrirait ensuite des lignes illisibles : on refuse.
	if conn, err := net.DialTimeout("tcp", cfg.Addr, 500*time.Millisecond); err == nil {
		conn.Close()
		return fmt.Errorf("un serveur répond sur %s : arrêtez-le avant de changer la passphrase", cfg.Addr)
	}

	oldPass, newPass, err := readRekeyPassphrases(*fromStdin)
	if err != nil {
		return err
	}
	if oldPass == newPass {
		return errors.New("la nouvelle passphrase est identique à l'ancienne")
	}

	store, err := OpenStore(cfg.DB, oldPass)
	if err != nil {
		if errors.Is(err, ErrBadPassphrase) {
			return errors.New("ancienne passphrase incorrecte")
		}
		return err
	}
	defer store.Close()

	fmt.Fprintf(os.Stderr, "Rechiffrement de %s…\n", cfg.DB)
	n, err := store.Rekey(newPass)
	if err != nil {
		return fmt.Errorf("rechiffrement annulé, la base n'a pas été modifiée : %w", err)
	}
	fmt.Fprintf(os.Stderr, "Passphrase changée : %d credential(s) rechiffré(s).\n", n)
	return nil
}

func readRekeyPassphrases(fromStdin bool) (oldPass, newPass string, err error) {
	if fromStdin {
		sc := bufio.NewScanner(os.Stdin)
		lines := make([]string, 0, 2)
		for len(lines) < 2 && sc.Scan() {
			lines = append(lines, strings.TrimRight(sc.Text(), "\r"))
		}
		if err := sc.Err(); err != nil {
			return "", "", err
		}
		if len(lines) < 2 || lines[0] == "" || lines[1] == "" {
			return "", "", errors.New("-stdin attend deux lignes non vides : ancienne puis nouvelle passphrase")
		}
		return lines[0], lines[1], nil
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", "", errors.New("aucun terminal : utilisez -stdin")
	}
	if oldPass, err = prompt("Passphrase actuelle : "); err != nil {
		return
	}
	if newPass, err = prompt("Nouvelle passphrase : "); err != nil {
		return
	}
	if strings.TrimSpace(newPass) == "" {
		return "", "", errors.New("passphrase vide")
	}
	confirm, err := prompt("Confirmation : ")
	if err != nil {
		return
	}
	if confirm != newPass {
		return "", "", errors.New("les passphrases ne correspondent pas")
	}
	return oldPass, newPass, nil
}
