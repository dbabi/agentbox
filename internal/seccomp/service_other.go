//go:build !linux

package seccomp

import "errors"

// InstallService is Linux only: services run only on the box.
func InstallService() (before, after int, err error) {
	return 0, 0, errors.New("seccomp: the service filter needs Linux")
}
