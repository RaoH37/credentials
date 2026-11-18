package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/RaoH37/credentials/internal/config"
	"github.com/RaoH37/credentials/internal/server"
	"github.com/RaoH37/credentials/internal/store"
)

func runServe(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("credentials", flag.ContinueOnError)
	fs.SetOutput(stderr)
	resolve := config.Flags(fs)
	showVersion := fs.Bool("version", false, "print the version and exit")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "Usage:\n"+
			"  credentials [options]          start the server\n"+
			"  credentials rekey [options]    change the database passphrase (see: credentials rekey -h)\n\n"+
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
	if *showVersion {
		fmt.Fprintln(os.Stdout, buildVersion())
		return nil
	}

	cfg, err := resolve()
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewTextHandler(stderr, nil))

	if err := os.MkdirAll(filepath.Dir(cfg.DB), 0o700); err != nil {
		return fmt.Errorf("create database directory: %w", err)
	}
	_, statErr := os.Stat(cfg.DB)
	isNew := errors.Is(statErr, os.ErrNotExist)

	pass, err := readPassphrase(isNew, stderr)
	if err != nil {
		return err
	}
	if isNew {
		if err := checkNewPassphrase(pass); err != nil {
			return err
		}
	}

	st, err := store.Open(ctx, cfg.DB, pass)
	clear(pass)
	if err != nil {
		if errors.Is(err, store.ErrLocked) {
			return fmt.Errorf("%s: %w (is another server running?)", cfg.DB, err)
		}
		return err
	}
	defer st.Close()

	// Listen before announcing, so that "address in use" is reported early.
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Handler:           server.New(st, logger),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()

	logger.Info("server started",
		"version", buildVersion(),
		"db", cfg.DB,
		"api", "http://"+ln.Addr().String()+"/credentials",
		"admin", "http://"+ln.Addr().String()+"/admin")

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
