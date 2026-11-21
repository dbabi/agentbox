//go:build !linux

package audit

import "testing"

// chattr flags exist only on Linux; see unlock_linux_test.go.
func tempDir(t testing.TB) string { return t.TempDir() }
func unlock(testing.TB, string)   {}
