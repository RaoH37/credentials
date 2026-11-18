package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Config regroupe les paramètres de lancement. Ordre de priorité :
// options de ligne de commande > fichier TOML (-config) > valeurs par défaut.
type Config struct {
	Addr string `toml:"addr"`
	DB   string `toml:"db"`
}

// commonFlags déclare -config, -addr et -db sur fs et renvoie une fonction qui,
// après fs.Parse, calcule la configuration effective.
func commonFlags(fs *flag.FlagSet) func() (Config, error) {
	configPath := fs.String("config", "", "fichier de configuration TOML (clés : addr, db)")
	addr := fs.String("addr", "", "adresse d'écoute, loopback uniquement (défaut : 127.0.0.1:12345)")
	db := fs.String("db", "", "chemin du fichier SQLite (défaut : $XDG_DATA_HOME/credentials/credentials.db, soit ~/.local/share/credentials/credentials.db)")
	return func() (Config, error) {
		cfg := Config{Addr: "127.0.0.1:12345"}
		if *configPath != "" {
			if err := loadConfigFile(*configPath, &cfg); err != nil {
				return cfg, err
			}
		}
		if *addr != "" {
			cfg.Addr = *addr
		}
		if *db != "" {
			cfg.DB = *db
		}
		if cfg.DB == "" {
			p, err := defaultDBPath()
			if err != nil {
				return cfg, err
			}
			cfg.DB = p
		}
		return cfg, nil
	}
}

func loadConfigFile(path string, cfg *Config) error {
	md, err := toml.DecodeFile(path, cfg)
	if err != nil {
		return fmt.Errorf("lecture de la configuration %s : %w", path, err)
	}
	if undec := md.Undecoded(); len(undec) > 0 {
		return fmt.Errorf("configuration %s : clé inconnue %q", path, undec[0].String())
	}
	return nil
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
