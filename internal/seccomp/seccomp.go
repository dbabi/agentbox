// Package seccomp builds seccomp-task.json, the profile every task runs with (ARCHITECTURE.md §4.2 "No btrfs ioctls",
// §10). It starts from podman's default profile and takes the btrfs ioctls out: the release ships the result and
// install.sh puts it at /var/lib/agentbox/control/seccomp-task.json.
//
// common.json is containers/common's pkg/seccomp/seccomp.json at common/v0.66.0 (Apache-2.0), the version podman 5.7
// builds with, copied unchanged from github.com/containers/container-libs.
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

// The btrfs ioctl type byte (BTRFS_IOCTL_MAGIC): every subvolume, snapshot, setflags and FICLONE command has it in cmd
// bits 8-15.
const (
	btrfsMagic = 0x94
	eopnotsupp = 95
	typeMask   = 0xff00
)

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
	removed := 0
	for n, s := range p.Syscalls {
		if i := slices.Index(s.Names, "ioctl"); i >= 0 {
			// libseccomp drops a conditional rule when an unconditional one exists for the same syscall, so the allow
			// below works only once ioctl is gone from every rule without args.
			if s.Action != "SCMP_ACT_ALLOW" || len(s.Args) > 0 || len(bytes.TrimSpace(s.Includes)) > 2 || len(bytes.TrimSpace(s.Excludes)) > 2 {
				return nil, fmt.Errorf("common.json: an ioctl rule this package doesn't expect: %+v", s)
			}
			p.Syscalls[n].Names = slices.Delete(slices.Clone(s.Names), i, i+1)
			removed++
		}
	}
	if removed != 1 {
		return nil, fmt.Errorf("common.json: %d unconditional ioctl rules, want 1", removed)
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
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "\t")
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
