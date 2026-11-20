//go:build !linux

package seal

import "errors"

var errNotLinux = errors.New("audit segments: Linux only")

// Box is Linux only; rootd runs only on the box.
type Box struct{}

func (Box) Flags(string) (bool, bool, error) { return false, false, errNotLinux }
func (Box) SetAppend(string) error           { return errNotLinux }
func (Box) SetImmutable(string) error        { return errNotLinux }
func (Box) Chown(string) error               { return errNotLinux }
