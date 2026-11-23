//go:build !linux

package rootd

import "errors"

func exchange(string, string) error { return errors.New("rootd runs on Linux only") }
