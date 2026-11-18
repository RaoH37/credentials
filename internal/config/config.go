// Package config resolves the runtime configuration from defaults, an
// optional TOML file and command-line flags.
package config

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// DefaultAddr is the default listen address.
const DefaultAddr = "127.0.0.1:12345"

// Config holds the runtime settings. Precedence: flags > TOML file > defaults.
type Config struct {
	Addr string `toml:"addr"`
	DB   string `toml:"db"`
}

// Flags registers -config, -addr and -db on fs. Call the returned function
// after fs.Parse to obtain the resolved, validated configuration.
func Flags(fs *flag.FlagSet) func() (Config, error) {
	path := fs.String("config", "", "TOML configuration `file` (keys: addr, db)")
	addr := fs.String("addr", "", "listen `address`, loopback only (default "+DefaultAddr+")")
	db := fs.String("db", "", "SQLite database `path` (default $XDG_DATA_HOME/credentials/credentials.db)")
	return func() (Config, error) {
		cfg := Config{Addr: DefaultAddr}
		if *path != "" {
			if err := LoadFile(*path, &cfg); err != nil {
				return Config{}, err
			}
		}
		if *addr != "" {
			cfg.Addr = *addr
		}
		if *db != "" {
			cfg.DB = *db
		}
		if cfg.DB == "" {
			p, err := DefaultDBPath()
			if err != nil {
				return Config{}, err
			}
			cfg.DB = p
		}
		return cfg, cfg.Validate()
	}
}

// LoadFile decodes the TOML file at path into cfg. Unknown keys are rejected
// so that typos do not go unnoticed.
func LoadFile(path string, cfg *Config) error {
	md, err := toml.DecodeFile(path, cfg)
	if err != nil {
		return fmt.Errorf("read config %s: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return fmt.Errorf("config %s: unknown key %q", path, undecoded[0].String())
	}
	return nil
}

// Validate checks the configuration.
func (c Config) Validate() error {
	if err := CheckLoopback(c.Addr); err != nil {
		return err
	}
	if c.DB == "" {
		return errors.New("database path is empty")
	}
	return nil
}

// DefaultDBPath follows the XDG Base Directory specification:
// $XDG_DATA_HOME/credentials/credentials.db, or ~/.local/share/... when
// XDG_DATA_HOME is unset. This keeps the database out of any source tree.
func DefaultDBPath() (string, error) {
	dir := os.Getenv("XDG_DATA_HOME")
	if dir == "" || !filepath.IsAbs(dir) { // the spec says relative values must be ignored
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home directory, use -db: %w", err)
		}
		dir = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(dir, "credentials", "credentials.db"), nil
}

// CheckLoopback rejects listen addresses that are not on a loopback
// interface: the API has no authentication and must not be exposed.
func CheckLoopback(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", addr, err)
	}
	if port == "" {
		return fmt.Errorf("invalid listen address %q: missing port", addr)
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("refusing to listen on %q: only loopback addresses (127.0.0.1, ::1, localhost) are allowed", host)
}
