package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// termSize is the admin terminal's size, or 24x80 when stdout is not a terminal.
func termSize(f *os.File) (int, int) {
	ws, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	if err != nil || ws.Row == 0 || ws.Col == 0 {
		return 24, 80
	}
	return int(ws.Row), int(ws.Col)
}

// rawTerm puts a terminal stdin in raw mode, so keys reach the session as typed; it returns the restore.
func rawTerm(f *os.File) func() {
	fd := int(f.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return func() {}
	}
	t := *old
	t.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	t.Oflag &^= unix.OPOST
	t.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	t.Cflag &^= unix.CSIZE | unix.PARENB
	t.Cflag |= unix.CS8
	t.Cc[unix.VMIN], t.Cc[unix.VTIME] = 1, 0
	if unix.IoctlSetTermios(fd, unix.TCSETS, &t) != nil {
		return func() {}
	}
	return func() { unix.IoctlSetTermios(fd, unix.TCSETS, old) }
}

// noEcho turns off a terminal stdin's echo for a secret typed at a prompt, keeping line editing; it returns the
// restore, and false when f is no terminal.
func noEcho(f *os.File) (func(), bool) {
	fd := int(f.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return func() {}, false
	}
	t := *old
	t.Lflag &^= unix.ECHO
	t.Lflag |= unix.ICANON | unix.ECHONL
	if unix.IoctlSetTermios(fd, unix.TCSETS, &t) != nil {
		return func() {}, false
	}
	return func() { unix.IoctlSetTermios(fd, unix.TCSETS, old) }, true
}
