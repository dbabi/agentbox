package seccomp

import (
	"encoding/binary"
	"testing"
)

// run interprets p on one struct seccomp_data, as the kernel's classic BPF does for the opcodes ServiceProgram uses.
func run(t *testing.T, p []Insn, nr, arch uint32, arg1 uint64) uint32 {
	t.Helper()
	d := make([]byte, 64)
	binary.LittleEndian.PutUint32(d[offNr:], nr)
	binary.LittleEndian.PutUint32(d[offArch:], arch)
	binary.LittleEndian.PutUint64(d[16+8:], arg1)
	var a uint32
	for pc := 0; pc < len(p); pc++ {
		x := p[pc]
		switch x.Code {
		case bpfLdWAbs:
			a = binary.LittleEndian.Uint32(d[x.K:])
		case bpfAndK:
			a &= x.K
		case bpfJeqK, bpfJgeK:
			hit := a == x.K
			if x.Code == bpfJgeK {
				hit = a >= x.K
			}
			if hit {
				pc += int(x.Jt)
			} else {
				pc += int(x.Jf)
			}
		case bpfRetK:
			return x.K
		default:
			t.Fatalf("opcode %#x at %d", x.Code, pc)
		}
	}
	t.Fatal("ran off the end of the program")
	return 0
}

// Every 16-bit ioctl cmd, with and without high bits set, gets EOPNOTSUPP exactly when its type byte is 0x94; other
// calls are allowed; another architecture and an x32 call are killed (§2 Common hardening, A-G13).
func TestServiceProgram(t *testing.T) {
	for _, c := range []struct {
		goarch      string
		arch, ioctl uint32
	}{{"arm64", 0xc00000b7, 29}, {"amd64", 0xc000003e, 16}} {
		p, err := ServiceProgram(c.goarch)
		if err != nil {
			t.Fatal(err)
		}
		if len(p) > 255 {
			t.Fatal("a jump can't reach past 255 instructions")
		}
		for cmd := uint64(0); cmd < 1<<16; cmd++ {
			want := uint32(retAllow)
			if cmd>>8&0xff == btrfsMagic {
				want = retErrno | eopnotsupp
			}
			for _, hi := range []uint64{0, 0xdead00000000, 0xffffffff00000000} {
				if got := run(t, p, c.ioctl, c.arch, cmd|hi); got != want {
					t.Fatalf("%s ioctl %#x: %#x, want %#x", c.goarch, cmd|hi, got, want)
				}
			}
		}
		// BTRFS_IOC_SUBVOL_CREATE as a number for another syscall is no ioctl
		for _, nr := range []uint32{0, 1, c.ioctl - 1, c.ioctl + 1, 435} {
			if got := run(t, p, nr, c.arch, 0x5000940e); got != retAllow {
				t.Errorf("%s syscall %d: %#x, want allow", c.goarch, nr, got)
			}
		}
		if got := run(t, p, c.ioctl, 0x40000003, 0x5000940e); got != retKillProcess { // AUDIT_ARCH_I386
			t.Errorf("%s: a compat-arch ioctl gets %#x, want kill", c.goarch, got)
		}
	}
	p, _ := ServiceProgram("amd64")
	if got := run(t, p, x32Bit|514, 0xc000003e, 0x5000940e); got != retKillProcess { // x32's ioctl
		t.Errorf("amd64: an x32 ioctl gets %#x, want kill", got)
	}
	if _, err := ServiceProgram("riscv64"); err == nil {
		t.Error("a filter for an architecture agentbox doesn't ship")
	}
}
