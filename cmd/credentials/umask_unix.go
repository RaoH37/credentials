//go:build unix

package main

import "syscall"

// restrictUmask ensures every file created by the process (database, WAL,
// lock file, directories) is accessible by its owner only.
func restrictUmask() {
	syscall.Umask(0o077)
}
