// Package wsfs is the one way root-side code reads an agent-writable tree: a workspace or a session-home
// (ARCHITECTURE.md §5.3). The agent controls every name and type in it, and can swap any of them between two calls, so
// nothing here resolves a path through a name it did not just open itself:
//   - every open is openat2 from an already open dir with RESOLVE_BENEATH, RESOLVE_NO_SYMLINKS and
//     RESOLVE_NO_MAGICLINKS (a per-name O_NOFOLLOW openat off Linux, for tests), with O_NONBLOCK, so a FIFO can't
//     block the reader;
//   - a file is read only if fstat on the open fd says it is regular, so a FIFO, device or socket swapped in after the
//     listing is refused;
//   - every read has a size cap, so a sparse file of any size costs at most the cap.
//
// A symlink is never followed: a walk reports it, with its target, as a link.
package wsfs

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

var (
	// ErrNotRegular is a file that is not a regular file when opened: a FIFO, a device, a socket, a dir or a symlink.
	ErrNotRegular = errors.New("not a regular file")
	// ErrTooLarge is a file over the reader's cap.
	ErrTooLarge = errors.New("over the size cap")
)

// MaxDepth bounds a walk: each level holds one open dir, and a tree any deeper than this is refused.
const MaxDepth = 256

// Entry is one entry of a walk, from fstatat on its parent's open dir.
type Entry struct {
	Rel   string      // slash-separated, relative to the walk's root; "." for the root
	Name  string      // base name
	Mode  fs.FileMode // type and permission bits
	Size  int64
	Ctime time.Time // a session can't set ctime back, so it bounds when the entry last changed
	dir   int       // the parent's fd, open only during the callback
}

func (e Entry) IsDir() bool { return e.Mode.IsDir() }

// File is an open regular file and its size at open.
type File struct {
	*os.File
	Size int64
}

// Open opens a regular file entry for reading. It is valid only inside the walk's callback.
func (e Entry) Open() (*File, error) {
	if e.dir < 0 {
		return nil, ErrNotRegular // the root is a dir
	}
	return openFile(e.dir, e.Name)
}

// Readlink returns a symlink entry's target, which is never followed.
func (e Entry) Readlink() (string, error) {
	buf := make([]byte, unix.PathMax)
	n, err := unix.Readlinkat(e.dir, e.Name, buf)
	if err != nil {
		return "", &fs.PathError{Op: "readlinkat", Path: e.Rel, Err: err}
	}
	return string(buf[:n]), nil
}

// Walk calls fn for root (Rel ".") and every entry under it, depth first, in lexical order, the way
// filepath.WalkDir does. fn returning fs.SkipDir for a dir skips what is under it. A symlink is passed to fn and not
// followed. root itself is trusted: it is a path rootd built, not one the agent chose.
func Walk(root string, fn func(Entry) error) error {
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return &fs.PathError{Op: "open", Path: root, Err: err}
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	e := entry(".", ".", -1, &st)
	if err := fn(e); err != nil {
		if err == fs.SkipDir {
			return nil
		}
		return err
	}
	return walkDir(fd, ".", 1, fn)
}

func walkDir(fd int, rel string, depth int, fn func(Entry) error) error {
	if depth > MaxDepth {
		return fmt.Errorf("%s: more than %d dirs deep", rel, MaxDepth)
	}
	names, err := readNames(fd)
	if err != nil {
		return &fs.PathError{Op: "readdir", Path: rel, Err: err}
	}
	for _, name := range names {
		r := name
		if rel != "." {
			r = rel + "/" + name
		}
		var st unix.Stat_t
		if err := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue // removed since the listing
			}
			return &fs.PathError{Op: "fstatat", Path: r, Err: err}
		}
		e := entry(r, name, fd, &st)
		err := fn(e)
		if err == fs.SkipDir || (err == nil && !e.IsDir()) {
			continue
		}
		if err != nil {
			return err
		}
		sub, err := openDir(fd, name)
		if err != nil {
			return &fs.PathError{Op: "openat2", Path: r, Err: err}
		}
		err = walkDir(sub, r, depth+1, fn)
		unix.Close(sub)
		if err != nil {
			return err
		}
	}
	return nil
}

func readNames(fd int) ([]string, error) {
	d, err := unix.Dup(fd)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(d), "dir")
	defer f.Close()
	names, err := f.Readdirnames(-1)
	slices.Sort(names)
	return names, err
}

func entry(rel, name string, dir int, st *unix.Stat_t) Entry {
	m := fs.FileMode(st.Mode & 0o777)
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		m |= fs.ModeDir
	case unix.S_IFLNK:
		m |= fs.ModeSymlink
	case unix.S_IFIFO:
		m |= fs.ModeNamedPipe
	case unix.S_IFSOCK:
		m |= fs.ModeSocket
	case unix.S_IFCHR:
		m |= fs.ModeDevice | fs.ModeCharDevice
	case unix.S_IFBLK:
		m |= fs.ModeDevice
	}
	return Entry{Rel: rel, Name: name, Mode: m, Size: st.Size, Ctime: time.Unix(st.Ctim.Unix()), dir: dir}
}

var openFn = openat // tests swap in openatNames

func openFile(dir int, rel string) (*File, error) {
	fd, err := openFn(dir, rel, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC)
	if err != nil {
		return nil, &fs.PathError{Op: "openat2", Path: rel, Err: err}
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		if err == nil {
			err = ErrNotRegular
		}
		return nil, &fs.PathError{Op: "open", Path: rel, Err: err}
	}
	return &File{os.NewFile(uintptr(fd), rel), st.Size}, nil
}

func openDir(dir int, name string) (int, error) {
	return openFn(dir, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NONBLOCK|unix.O_CLOEXEC)
}

// ReadFile reads the regular file rel (slash-separated, below root) in full. Any symlink, "..", or absolute path on
// the way is refused, and so is a file over max bytes.
func ReadFile(root, rel string, max int64) ([]byte, error) {
	if rel == "" || strings.HasPrefix(rel, "/") || slices.Contains(strings.Split(rel, "/"), "..") {
		return nil, &fs.PathError{Op: "open", Path: rel, Err: fs.ErrInvalid}
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: root, Err: err}
	}
	defer unix.Close(fd)
	f, err := openFile(fd, rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.ReadAll(max)
}

// ReadAll reads the whole file, refusing one that is, or grows, over max bytes.
func (f *File) ReadAll(max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err == nil && int64(len(b)) > max {
		err = &fs.PathError{Op: "read", Path: f.Name(), Err: ErrTooLarge}
	}
	return b, err
}
