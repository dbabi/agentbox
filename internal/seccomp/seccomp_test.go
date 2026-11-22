package seccomp

import (
	"encoding/json"
	"slices"
	"testing"
)

// §4.2: no unconditional ioctl rule, and every 16-bit cmd, with and without high bits set, matches exactly one rule:
// EOPNOTSUPP for type 0x94, allow for every other type.
func TestTaskIoctl(t *testing.T) {
	b, err := Task()
	if err != nil {
		t.Fatal(err)
	}
	var p Profile
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	var rules []Syscall
	for _, s := range p.Syscalls {
		if !slices.Contains(s.Names, "ioctl") {
			continue
		}
		if len(s.Args) == 0 {
			t.Fatalf("unconditional ioctl rule: %+v", s)
		}
		for _, a := range s.Args {
			if a.Op != "SCMP_CMP_MASKED_EQ" || a.Index != 1 || a.Value&^typeMask != 0 {
				t.Fatalf("ioctl rule outside cmd bits 8-15: %+v", s)
			}
		}
		rules = append(rules, s)
	}
	if len(rules) != 9 {
		t.Fatalf("%d ioctl rules, want 9", len(rules))
	}
	for _, high := range []uint64{0, 0xffffffff00000000, 0x8000000000000000, 0xdead0000, 0xffff0000} {
		for cmd := uint64(0); cmd < 1<<16; cmd++ {
			arg := cmd | high
			var hit []Syscall
			for _, r := range rules {
				if arg&r.Args[0].Value == r.Args[0].ValueTwo {
					hit = append(hit, r)
				}
			}
			if cmd>>8 == btrfsMagic {
				if len(hit) != 1 || hit[0].Action != "SCMP_ACT_ERRNO" || hit[0].ErrnoRet == nil || *hit[0].ErrnoRet != 95 {
					t.Fatalf("cmd %#x: %d rules, want EOPNOTSUPP only: %+v", arg, len(hit), hit)
				}
				continue
			}
			if len(hit) == 0 {
				t.Fatalf("cmd %#x matches no rule: the default ENOSYS would break it", arg)
			}
			for _, h := range hit {
				if h.Action != "SCMP_ACT_ALLOW" {
					t.Fatalf("cmd %#x: %+v", arg, h)
				}
			}
		}
	}
	// FICLONE and BTRFS_IOC_SNAP_CREATE_V2: the real commands, sizes and directions in the high bits included
	for _, c := range []uint64{0x40049409, 0x50009417, 0x5000940e} {
		if c&typeMask != btrfsMagic<<8 {
			t.Fatalf("%#x is not type 0x94", c)
		}
	}
	// every other syscall rule stays as podman ships it
	var src Profile
	json.Unmarshal(common, &src)
	if len(p.Syscalls) != len(src.Syscalls)+9 || p.DefaultAction != src.DefaultAction {
		t.Fatalf("%d rules from %d, default %s", len(p.Syscalls), len(src.Syscalls), p.DefaultAction)
	}
}
