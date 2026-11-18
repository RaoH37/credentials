//go:build !unix

package store

import "os"

// lockFile is a best-effort fallback on platforms without flock: it only
// creates the lock file and provides no mutual exclusion.
func lockFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
}
