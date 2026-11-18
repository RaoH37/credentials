package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:12345", "adresse d'écoute (gardez une adresse loopback)")
	dbPath := flag.String("db", "", "chemin du fichier SQLite (défaut : $XDG_DATA_HOME/credentials/credentials.db, soit ~/.local/share/credentials/credentials.db)")
	flag.Parse()

	if *dbPath == "" {
		p, err := defaultDBPath()
		if err != nil {
			log.Fatal(err)
		}
		*dbPath = p
	}
	// Le dossier de la base n'est lisible que par l'utilisateur courant.
	if err := os.MkdirAll(filepath.Dir(*dbPath), 0o700); err != nil {
		log.Fatalf("création du dossier de la base : %v", err)
	}
	log.Printf("Base    : %s", *dbPath)

	if err := checkLoopback(*addr); err != nil {
		log.Fatal(err)
	}

	pass, err := readPassphrase(*dbPath)
	if err != nil {
		log.Fatal(err)
	}

	store, err := OpenStore(*dbPath, pass)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	srv := &http.Server{
		Addr:              *addr,
		Handler:           NewServer(store).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("API     : http://%s/credentials", *addr)
	log.Printf("Admin   : http://%s/admin", *addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

// defaultDBPath suit la spécification XDG : $XDG_DATA_HOME, sinon
// ~/.local/share. La base reste ainsi hors de tout dépôt Git.
func defaultDBPath() (string, error) {
	dir := os.Getenv("XDG_DATA_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("dossier personnel introuvable, utilisez -db : %w", err)
		}
		dir = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(dir, "credentials", "credentials.db"), nil
}

// checkLoopback refuse d'écouter ailleurs que sur une interface locale : l'API
// n'a pas d'authentification, elle ne doit pas être exposée sur le réseau.
func checkLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("adresse invalide %q : %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("refus d'écouter sur %q : seule une adresse loopback (127.0.0.1, ::1, localhost) est autorisée", host)
}

// readPassphrase lit la passphrase depuis CREDENTIALS_PASSPHRASE ou, à défaut,
// la demande sur le terminal (avec confirmation si la base n'existe pas encore).
func readPassphrase(dbPath string) (string, error) {
	if p := os.Getenv("CREDENTIALS_PASSPHRASE"); p != "" {
		return p, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("aucun terminal : définissez CREDENTIALS_PASSPHRASE")
	}
	_, statErr := os.Stat(dbPath)
	isNew := errors.Is(statErr, os.ErrNotExist)

	p, err := prompt("Passphrase : ")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(p) == "" {
		return "", errors.New("passphrase vide")
	}
	if isNew {
		fmt.Fprintln(os.Stderr, "Nouvelle base : cette passphrase chiffrera tous les credentials. Elle n'est stockée nulle part.")
		c, err := prompt("Confirmation : ")
		if err != nil {
			return "", err
		}
		if c != p {
			return "", errors.New("les passphrases ne correspondent pas")
		}
	}
	return p, nil
}

func prompt(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return string(b), err
}
