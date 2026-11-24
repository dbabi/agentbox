package seccomp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"testing"
)

// common.json is upstream's file, byte for byte: re-vendor it with the commit and sha256 in seccomp.go.
func TestCommonPinned(t *testing.T) {
	if h := sha256.Sum256(common); hex.EncodeToString(h[:]) != commonSHA256 {
		t.Fatalf("common.json sha256 %x, want %s", h, commonSHA256)
	}
}

func task(t *testing.T) Profile {
	t.Helper()
	b, err := Task()
	if err != nil {
		t.Fatal(err)
	}
	var p Profile
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

// eval returns what a task with no capabilities gets from name(args...): "allow", the errno, or the default. It fails
// on two matching rules with different outcomes, which libseccomp has no defined order for.
func eval(t *testing.T, p Profile, name string, args ...uint64) string {
	t.Helper()
	out := ""
	for _, s := range p.Syscalls {
		if !slices.Contains(s.Names, name) || len(s.Includes) > 2 {
			continue // includes: only with a capability (or arch) a task doesn't have
		}
		hit := true
		for _, a := range s.Args {
			v := args[a.Index]
			switch a.Op {
			case "SCMP_CMP_MASKED_EQ":
				hit = hit && v&a.Value == a.ValueTwo
			case "SCMP_CMP_EQ":
				hit = hit && v == a.Value
			case "SCMP_CMP_NE":
				hit = hit && v != a.Value
			default:
				t.Fatalf("op %s in %+v", a.Op, s)
			}
		}
		if !hit {
			continue
		}
		r := "allow"
		if s.Action == "SCMP_ACT_ERRNO" {
			r = s.Errno
		} else if s.Action != "SCMP_ACT_ALLOW" {
			t.Fatalf("action %s in %+v", s.Action, s)
		}
		if out != "" && out != r {
			t.Fatalf("%s%v: rules disagree, %s and %s", name, args, out, r)
		}
		out = r
	}
	if out == "" {
		return "default"
	}
	return out
}

// #155: only AF_UNIX, AF_INET, AF_INET6 and NETLINK_ROUTE sockets, on the low 32 bits; socketpair AF_UNIX only; no
// namespaces from clone, unshare or setns; clone3 ENOSYS.
func TestTaskSocketsAndNamespaces(t *testing.T) {
	p := task(t)
	if p.DefaultAction != "SCMP_ACT_ERRNO" || p.DefaultErrnoRet == nil || *p.DefaultErrnoRet != enosys {
		t.Fatalf("default %s %v, want ENOSYS", p.DefaultAction, p.DefaultErrnoRet)
	}
	if len(p.ArchMap) != 0 {
		t.Fatalf("archMap %s: a compat architecture gets around the argument rules", p.ArchMap)
	}
	for _, s := range p.Syscalls {
		for _, n := range plain {
			if slices.Contains(s.Names, n) && len(s.Args) == 0 && len(s.Includes) <= 2 && len(s.Excludes) <= 2 && s.Action == "SCMP_ACT_ALLOW" {
				t.Fatalf("unconditional %s allow: %+v", n, s)
			}
		}
	}
	const hi = 0x100000000
	for _, c := range []struct {
		name string
		args []uint64
		want string
	}{
		{"socket", []uint64{1, 1, 0}, "allow"},                      // AF_UNIX: the broker sockets
		{"socket", []uint64{2, 1, 0}, "allow"},                      // AF_INET: the loopback forwarders
		{"socket", []uint64{10, 2, 0}, "allow"},                     // AF_INET6
		{"socket", []uint64{2 | 0xffffffff00000000, 1, 0}, "allow"}, // the kernel sees AF_INET
		{"socket", []uint64{16, 3, 0}, "allow"},                     // NETLINK_ROUTE
		{"socket", []uint64{16, 3, 9}, "default"},                   // NETLINK_AUDIT
		{"socket", []uint64{16, 3, hi | 9}, "default"},
		{"socket", []uint64{16, 3, 15}, "default"},     // NETLINK_KOBJECT_UEVENT
		{"socket", []uint64{38, 5, 0}, "default"},      // AF_ALG
		{"socket", []uint64{40, 1, 0}, "default"},      // AF_VSOCK
		{"socket", []uint64{hi | 40, 1, 0}, "default"}, // AF_VSOCK, high bits set
		{"socket", []uint64{hi | 38, 5, 0}, "default"},
		{"socket", []uint64{17, 3, 0}, "default"}, // AF_PACKET
		{"socket", []uint64{0, 1, 0}, "default"},
		{"socket", []uint64{hi, 1, 0}, "default"},
		{"socketpair", []uint64{1, 1, 0}, "allow"},
		{"socketpair", []uint64{hi | 1, 1, 0}, "allow"},
		{"socketpair", []uint64{2, 1, 0}, "default"},
		{"socketpair", []uint64{30, 5, 0}, "default"},    // AF_TIPC, which upstream allows
		{"clone", []uint64{0x3d0f00, 0}, "allow"},        // a pthread
		{"clone", []uint64{0x01200011, 0}, "allow"},      // fork
		{"clone", []uint64{0x10000000 | 17, 0}, "EPERM"}, // CLONE_NEWUSER
		{"clone", []uint64{0x40000000, 0}, "EPERM"},      // CLONE_NEWNET
		{"clone", []uint64{0x20000, 0}, "EPERM"},         // CLONE_NEWNS
		{"clone", []uint64{0x7e020000, 0}, "EPERM"},
		{"unshare", []uint64{0x200}, "allow"},      // CLONE_FS
		{"unshare", []uint64{0x10000000}, "EPERM"}, // unshare -U
		{"unshare", []uint64{0x10020000}, "EPERM"}, // unshare -Ur
		{"unshare", []uint64{0x80}, "EPERM"},       // CLONE_NEWTIME
		{"unshare", []uint64{0x02000000}, "EPERM"}, // CLONE_NEWCGROUP
		{"setns", []uint64{3, 0}, "EPERM"},
		{"clone3", []uint64{0, 0}, "ENOSYS"},
		{"socketcall", []uint64{1, 0}, "default"}, // #181: its args are in memory, out of seccomp's reach
		{"ipc", []uint64{23, 0}, "default"},
		{"copy_file_range", []uint64{3, 0, 4, 0, 1 << 30, 0}, "ENOSYS"}, // #205: a reflink across qgroups
	} {
		if got := eval(t, p, c.name, c.args...); got != c.want {
			t.Errorf("%s(%#x): %s, want %s", c.name, c.args, got, c.want)
		}
	}
	// each single flag bit: EPERM for a CLONE_NEW* bit, allowed otherwise
	for bit := uint(0); bit < 32; bit++ {
		f := uint64(1) << bit
		for n, m := range map[string]uint64{"clone": cloneNew, "unshare": unshareNew} {
			want := "allow"
			if f&m != 0 {
				want = "EPERM"
			}
			if got := eval(t, p, n, f, 0); got != want {
				t.Errorf("%s(%#x): %s, want %s", n, f, got, want)
			}
		}
	}
}

// §4.2: no unconditional ioctl rule, and every 16-bit cmd, with and without high bits set, matches exactly one rule:
// EOPNOTSUPP for type 0x94, allow for every other type.
func TestTaskIoctl(t *testing.T) {
	p := task(t)
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
	// every other syscall rule stays as upstream ships it
	var src Profile
	json.Unmarshal(common, &src)
	// the ioctl rules, 4 socket, 1 socketpair, 2 clone/unshare allows, 7 + 8 EPERMs, clone3 and copy_file_range, for
	// upstream's 7 socket rules
	if len(p.Syscalls) != len(src.Syscalls)+9+4+1+2+15+1+1-7 || p.DefaultAction != src.DefaultAction {
		t.Fatalf("%d rules from %d, default %s", len(p.Syscalls), len(src.Syscalls), p.DefaultAction)
	}
}
