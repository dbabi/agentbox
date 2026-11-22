// Package seccomp builds seccomp-task.json, the profile every task and attach session runs with (ARCHITECTURE.md §4.2
// "No btrfs ioctls", §10). It starts from podman's default profile, takes the btrfs ioctls out, allows only the socket
// families tasks need and keeps tasks from making namespaces: the release ships the result and install.sh puts it at
// /var/lib/agentbox/control/seccomp-task.json.
//
// common.json is common/pkg/seccomp/seccomp.json from github.com/podman-container-tools/container-libs at commit
// dadba8bfe851c24bc9ee712398fc3406a4e5673f (Apache-2.0), copied unchanged; commonSHA256 pins it. That commit masks the
// socket rules to 32 bits and restricts socketpair, fixes the profile in Ubuntu 26.04's containers-common 0.66.0
// lacks; the distro copy is never read.
package seccomp

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
)

//go:embed common.json
var common []byte

// commonSHA256 is the sha256 of common.json as fetched from upstream.
const commonSHA256 = "8f3b8bd95844912349e9d82674ef52ffeaad5782b2c34de739a1010828c36e7c"

// The btrfs ioctl type byte (BTRFS_IOCTL_MAGIC): every subvolume, snapshot, setflags and FICLONE command has it in cmd
// bits 8-15.
const (
	btrfsMagic = 0x94
	eopnotsupp = 95
	typeMask   = 0xff00
)

const (
	eperm  = 1
	enosys = 38
	// int arguments are compared on their low 32 bits: the kernel ignores the rest, so a rule on all 64 bits can be
	// sidestepped with high bits set (socket(0x100000028, ...) is AF_VSOCK).
	low32 = 0xffffffff
	// CLONE_NEWTIME, NEWNS, NEWCGROUP, NEWUTS, NEWIPC, NEWUSER, NEWPID, NEWNET. clone(2) takes the exit signal in bits
	// 0-7, so it can't ask for CLONE_NEWTIME (0x80).
	cloneNew   = 0x7e020000
	unshareNew = cloneNew | 0x80
)

// The socket families a task may open (AF_UNIX, AF_INET, AF_INET6), plus AF_NETLINK with NETLINK_ROUTE only. Any other
// family, AF_ALG and AF_VSOCK included, gets the default ENOSYS.
var families = []uint64{1, 2, 10}

const (
	afNetlink    = 16
	netlinkRoute = 0
)

// plain names the syscalls Task takes out of the profile's one unconditional allow rule.
var plain = []string{"ioctl", "clone", "clone3", "setns", "unshare"}

// Path is where install.sh puts the profile and rootd's task launch reads it.
const Path = "/var/lib/agentbox/control/seccomp-task.json"

type Profile struct {
	DefaultAction   string          `json:"defaultAction"`
	DefaultErrnoRet *uint           `json:"defaultErrnoRet,omitempty"`
	DefaultErrno    string          `json:"defaultErrno,omitempty"`
	ArchMap         json.RawMessage `json:"archMap,omitempty"`
	Syscalls        []Syscall       `json:"syscalls"`
}

type Syscall struct {
	Names    []string        `json:"names"`
	Action   string          `json:"action"`
	Args     []Arg           `json:"args"`
	Comment  string          `json:"comment"`
	Includes json.RawMessage `json:"includes,omitempty"`
	Excludes json.RawMessage `json:"excludes,omitempty"`
	ErrnoRet *uint           `json:"errnoRet,omitempty"`
	Errno    string          `json:"errno,omitempty"`
}

// Arg is one condition. For SCMP_CMP_MASKED_EQ, Value is the mask and ValueTwo the datum: (arg & Value) == ValueTwo.
type Arg struct {
	Index    uint   `json:"index"`
	Value    uint64 `json:"value"`
	ValueTwo uint64 `json:"valueTwo"`
	Op       string `json:"op"`
}

// Task returns seccomp-task.json.
func Task() ([]byte, error) {
	var p Profile
	d := json.NewDecoder(bytes.NewReader(common))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return nil, fmt.Errorf("common.json: %v", err)
	}
	for _, name := range plain {
		removed := 0
		for n, s := range p.Syscalls {
			i := slices.Index(s.Names, name)
			if i < 0 || len(bytes.TrimSpace(s.Includes)) > 2 || len(bytes.TrimSpace(s.Excludes)) > 2 {
				continue
			}
			// libseccomp drops a conditional rule when an unconditional one exists for the same syscall, so the rules
			// below work only once the name is gone from every rule without args.
			if s.Action != "SCMP_ACT_ALLOW" || len(s.Args) > 0 {
				return nil, fmt.Errorf("common.json: a %s rule this package doesn't expect: %+v", name, s)
			}
			p.Syscalls[n].Names = slices.Delete(slices.Clone(s.Names), i, i+1)
			removed++
		}
		if removed != 1 {
			return nil, fmt.Errorf("common.json: %d unconditional %s rules, want 1", removed, name)
		}
	}
	// Upstream's socket rules deny a few families; they are replaced by an allowlist.
	sockets := 0
	p.Syscalls = slices.DeleteFunc(p.Syscalls, func(s Syscall) bool {
		if slices.Contains(s.Names, "socket") || slices.Contains(s.Names, "socketpair") {
			sockets++
			return len(s.Names) == 1
		}
		return false
	})
	if sockets == 0 || slices.ContainsFunc(p.Syscalls, func(s Syscall) bool {
		return slices.Contains(s.Names, "socket") || slices.Contains(s.Names, "socketpair")
	}) {
		return nil, fmt.Errorf("common.json: socket rules this package doesn't expect")
	}
	// One allow rule per type bit: a command is allowed when that bit differs from BTRFS_IOCTL_MAGIC's.
	for bit := uint(8); bit < 16; bit++ {
		m := uint64(1) << bit
		want := m
		if btrfsMagic<<8&m != 0 {
			want = 0
		}
		p.Syscalls = append(p.Syscalls, Syscall{Names: []string{"ioctl"}, Action: "SCMP_ACT_ALLOW",
			Args: []Arg{{Index: 1, Value: m, ValueTwo: want, Op: "SCMP_CMP_MASKED_EQ"}}, Comment: fmt.Sprintf("ioctl: type bit %d differs from 0x94", bit)})
	}
	e := uint(eopnotsupp)
	p.Syscalls = append(p.Syscalls, Syscall{Names: []string{"ioctl"}, Action: "SCMP_ACT_ERRNO", ErrnoRet: &e, Errno: "EOPNOTSUPP",
		Args: []Arg{{Index: 1, Value: typeMask, ValueTwo: btrfsMagic << 8, Op: "SCMP_CMP_MASKED_EQ"}}, Comment: "btrfs ioctls (type 0x94): EOPNOTSUPP"})
	for _, f := range families {
		p.Syscalls = append(p.Syscalls, allow("socket", fmt.Sprintf("socket: family %d", f), Arg{Index: 0, Value: low32, ValueTwo: f, Op: "SCMP_CMP_MASKED_EQ"}))
	}
	p.Syscalls = append(p.Syscalls,
		allow("socket", "socket: AF_NETLINK with NETLINK_ROUTE only", Arg{Index: 0, Value: low32, ValueTwo: afNetlink, Op: "SCMP_CMP_MASKED_EQ"},
			Arg{Index: 2, Value: low32, ValueTwo: netlinkRoute, Op: "SCMP_CMP_MASKED_EQ"}),
		allow("socketpair", "socketpair: AF_UNIX only", Arg{Index: 0, Value: low32, ValueTwo: 1, Op: "SCMP_CMP_MASKED_EQ"}),
		// flags are arg 0 of clone and unshare on arm64 and amd64, the two architectures agentbox ships
		allow("clone", "clone: no CLONE_NEW* flag", Arg{Index: 0, Value: cloneNew, ValueTwo: 0, Op: "SCMP_CMP_MASKED_EQ"}),
		allow("unshare", "unshare: no CLONE_NEW* flag", Arg{Index: 0, Value: unshareNew, ValueTwo: 0, Op: "SCMP_CMP_MASKED_EQ"}))
	// One EPERM rule per CLONE_NEW* bit: they never overlap the allow rules above.
	for _, name := range []string{"clone", "unshare"} {
		m := uint64(cloneNew)
		if name == "unshare" {
			m = unshareNew
		}
		for bit := uint(0); bit < 32; bit++ {
			if f := uint64(1) << bit; m&f != 0 {
				p.Syscalls = append(p.Syscalls, deny(name, eperm, "EPERM", fmt.Sprintf("%s: CLONE_NEW* flag %#x", name, f),
					Arg{Index: 0, Value: f, ValueTwo: f, Op: "SCMP_CMP_MASKED_EQ"}))
			}
		}
	}
	// glibc and Go fall back to clone on ENOSYS; clone3's flags are in a struct seccomp can't read.
	p.Syscalls = append(p.Syscalls, deny("clone3", enosys, "ENOSYS", "clone3: ENOSYS, so callers fall back to clone"))
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "\t")
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func allow(name, comment string, args ...Arg) Syscall {
	return Syscall{Names: []string{name}, Action: "SCMP_ACT_ALLOW", Args: args, Comment: comment}
}

func deny(name string, errno uint, errnoName, comment string, args ...Arg) Syscall {
	return Syscall{Names: []string{name}, Action: "SCMP_ACT_ERRNO", ErrnoRet: &errno, Errno: errnoName, Args: args, Comment: comment}
}
