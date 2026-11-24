//go:build !linux

package wsfs

// openat off Linux (the unit tests on a Mac) has no openat2.
func openat(dir int, rel string, flags int) (int, error) { return openatNames(dir, rel, flags) }
