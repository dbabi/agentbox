package attach

import (
	"os"
	"os/user"
	"strconv"

	"golang.org/x/sys/unix"
)

// OpenPTY opens a PTY pair that rootd owns (§4.2): the master stays in rootd, the slave is the session's terminal,
// owned by the agent uid and group tty, mode 0620, as login(1) leaves it. Neither end becomes rootd's controlling tty.
func OpenPTY(uid, rows, cols int) (master, slave *os.File, err error) {
	m, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	master = os.NewFile(uintptr(m), "/dev/ptmx")
	fail := func(e error) (*os.File, *os.File, error) { master.Close(); return nil, nil, e }
	if err := unix.IoctlSetPointerInt(m, unix.TIOCSPTLCK, 0); err != nil {
		return fail(err)
	}
	n, err := unix.IoctlGetUint32(m, unix.TIOCGPTN)
	if err != nil {
		return fail(err)
	}
	name := "/dev/pts/" + strconv.FormatUint(uint64(n), 10)
	s, err := unix.Open(name, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail(err)
	}
	slave = os.NewFile(uintptr(s), name)
	gid := -1
	if g, err := user.LookupGroup("tty"); err == nil {
		gid, _ = strconv.Atoi(g.Gid)
	}
	if err := unix.Fchown(s, uid, gid); err != nil {
		slave.Close()
		return fail(err)
	}
	if err := unix.Fchmod(s, 0o620); err != nil {
		slave.Close()
		return fail(err)
	}
	ws := &unix.Winsize{Row: uint16(rows), Col: uint16(cols)}
	if err := unix.IoctlSetWinsize(m, unix.TIOCSWINSZ, ws); err != nil {
		slave.Close()
		return fail(err)
	}
	return master, slave, nil
}
