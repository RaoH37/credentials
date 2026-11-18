// Command credentials is a local credentials vault for development: an HTTP
// JSON API and an admin interface backed by an encrypted SQLite database.
//
// Usage:
//
//	credentials [-config file] [-addr address] [-db path]   start the server
//	credentials rekey [-config file] [-db path] [-stdin]    change the passphrase
//	credentials -version                                     print the version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
)

// version is set at build time: -ldflags "-X main.version=1.2.3".
var version = ""

func main() {
	restrictUmask()
	if err := run(context.Background(), os.Args[1:], os.Stderr); err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stderr, "credentials:", err)
		}
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stderr io.Writer) error {
	if len(args) > 0 && args[0] == "rekey" {
		return runRekey(ctx, args[1:], stderr)
	}
	return runServe(ctx, args, stderr)
}

// buildVersion returns the version injected at build time, falling back to
// the module version recorded by the Go toolchain.
func buildVersion() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		return bi.Main.Version
	}
	return "dev"
}
