package seal

import (
	"os"
	"os/user"
	"strconv"

	"golang.org/x/sys/unix"
)

const (
	fsAppendFL    = 0x20 // FS_APPEND_FL
	fsImmutableFL = 0x10 // FS_IMMUTABLE_FL
)

// Box is the real FS: inode flags through FS_IOC_GETFLAGS/SETFLAGS, owner agentbox-audit.
type Box struct{}

func flags(path string) (int, *os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, nil, err
	}
	v, err := unix.IoctlGetInt(int(f.Fd()), unix.FS_IOC_GETFLAGS)
	if err != nil {
		f.Close()
		return 0, nil, err
	}
	return v, f, nil
}

func (Box) Flags(path string) (bool, bool, error) {
	v, f, err := flags(path)
	if err != nil {
		return false, false, err
	}
	f.Close()
	return v&fsAppendFL != 0, v&fsImmutableFL != 0, nil
}

func set(path string, bit int) error {
	v, f, err := flags(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if v&bit != 0 {
		return nil
	}
	return unix.IoctlSetPointerInt(int(f.Fd()), unix.FS_IOC_SETFLAGS, v|bit)
}

func (Box) SetAppend(path string) error    { return set(path, fsAppendFL) }
func (Box) SetImmutable(path string) error { return set(path, fsImmutableFL) }

// AuditIDs returns agentbox-audit's uid and gid.
func AuditIDs() (int, int, error) {
	u, err := user.Lookup("agentbox-audit")
	if err != nil {
		return 0, 0, err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return uid, gid, nil
}

func (Box) Chown(path string) error {
	uid, gid, err := AuditIDs()
	if err != nil {
		return err
	}
	return os.Lchown(path, uid, gid)
}
