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

// version est injectée au build : -ldflags "-X main.version=1.2.3".
var version = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "rekey" {
		if err := runRekey(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "erreur :", err)
			os.Exit(1)
		}
		return
	}

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage :\n  %[1]s [options]          lance le serveur\n  %[1]s rekey [options]    change la passphrase de la base (%[1]s rekey -h)\n\nOptions :\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}
	resolve := commonFlags(flag.CommandLine)
	showVersion := flag.Bool("version", false, "affiche la version et quitte")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	cfg, err := resolve()
	if err != nil {
		log.Fatal(err)
	}

	if err := checkLoopback(cfg.Addr); err != nil {
		log.Fatal(err)
	}
	// Le dossier de la base n'est lisible que par l'utilisateur courant.
	if err := os.MkdirAll(filepath.Dir(cfg.DB), 0o700); err != nil {
		log.Fatalf("création du dossier de la base : %v", err)
	}
	log.Printf("Version : %s", version)
	log.Printf("Base    : %s", cfg.DB)

	pass, err := readPassphrase(cfg.DB)
	if err != nil {
		log.Fatal(err)
	}

	store, err := OpenStore(cfg.DB, pass)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	srv := &http.Server{
		Addr:              cfg.Addr,
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

	log.Printf("API     : http://%s/credentials", cfg.Addr)
	log.Printf("Admin   : http://%s/admin", cfg.Addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
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

// readPassphrase cherche la passphrase, dans l'ordre :
//  1. le credential systemd "passphrase" ($CREDENTIALS_DIRECTORY/passphrase),
//     déchiffré par systemd au lancement du service (LoadCredentialEncrypted) ;
//  2. la variable d'environnement CREDENTIALS_PASSPHRASE ;
//  3. une saisie sur le terminal (avec confirmation si la base est nouvelle).
func readPassphrase(dbPath string) (string, error) {
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		b, err := os.ReadFile(filepath.Join(dir, "passphrase"))
		if err == nil {
			p := strings.TrimRight(string(b), "\r\n")
			if p == "" {
				return "", errors.New("credential systemd « passphrase » vide")
			}
			return p, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("lecture du credential systemd : %w", err)
		}
	}
	if p := os.Getenv("CREDENTIALS_PASSPHRASE"); p != "" {
		return p, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("aucune passphrase : ni credential systemd, ni CREDENTIALS_PASSPHRASE, ni terminal")
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
