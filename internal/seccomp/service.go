package seccomp

import "fmt"

// The service filter (ARCHITECTURE.md §2 Common hardening, "No btrfs ioctls in services"): every non-root agentbox
// service installs it at start with seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC), under
// NoNewPrivileges, and exits if that fails. systemd's SystemCallFilter= can't match ioctl arguments, so the binary
// installs it itself. An ioctl whose type byte is 0x94 gets EOPNOTSUPP, as in seccomp-task.json, so no service can
// create a subvolume outside 2/0 in data/cache/, git/, state/ or memory/; another architecture kills the process.

// Insn is one classic BPF instruction (struct sock_filter).
type Insn struct {
	Code   uint16
	Jt, Jf uint8
	K      uint32
}

// Classic BPF opcodes and seccomp return values (linux/filter.h, linux/seccomp.h), kept here so the program builds
// and is tested on every OS.
const (
	bpfLdWAbs = 0x20 // BPF_LD | BPF_W | BPF_ABS
	bpfJeqK   = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	bpfJgeK   = 0x35 // BPF_JMP | BPF_JGE | BPF_K
	bpfAndK   = 0x54 // BPF_ALU | BPF_AND | BPF_K
	bpfRetK   = 0x06 // BPF_RET | BPF_K

	retAllow       = 0x7fff0000
	retErrno       = 0x00050000
	retKillProcess = 0x80000000

	// struct seccomp_data offsets: nr, arch, then args[6] from 16. Both shipped architectures are little-endian, so
	// args[1]'s low 32 bits are at 24: the kernel takes an ioctl cmd as an unsigned int, so high bits change nothing.
	offNr   = 0
	offArch = 4
	offArg1 = 24
	x32Bit  = 0x40000000 // __X32_SYSCALL_BIT: x32 calls carry AUDIT_ARCH_X86_64, so they are refused by number
)

// ServiceProgram is the service filter for goarch: kill on another architecture (and on any x32 call on amd64),
// EOPNOTSUPP for an ioctl with type byte 0x94, allow everything else.
func ServiceProgram(goarch string) ([]Insn, error) {
	var arch, ioctl uint32
	switch goarch {
	case "arm64":
		arch, ioctl = 0xc00000b7, 29 // AUDIT_ARCH_AARCH64, __NR_ioctl
	case "amd64":
		arch, ioctl = 0xc000003e, 16 // AUDIT_ARCH_X86_64
	default:
		return nil, fmt.Errorf("seccomp: no service filter for %s", goarch)
	}
	x32 := 0
	if goarch == "amd64" {
		x32 = 1
	}
	// the last three instructions are errno, allow and kill; a jump counts the instructions it skips
	n := 10 + x32
	errno, allow, kill := n-3, n-2, n-1
	to := func(at, target int) uint8 { return uint8(target - at - 1) }
	p := []Insn{{Code: bpfLdWAbs, K: offArch}, {Code: bpfJeqK, K: arch, Jf: to(1, kill)}, {Code: bpfLdWAbs, K: offNr}}
	if x32 == 1 {
		p = append(p, Insn{Code: bpfJgeK, K: x32Bit, Jt: to(3, kill)})
	}
	at := len(p)
	return append(p, Insn{Code: bpfJeqK, K: ioctl, Jf: to(at, allow)}, Insn{Code: bpfLdWAbs, K: offArg1},
		Insn{Code: bpfAndK, K: typeMask}, Insn{Code: bpfJeqK, K: btrfsMagic << 8, Jt: to(at+3, errno), Jf: to(at+3, allow)},
		Insn{Code: bpfRetK, K: retErrno | eopnotsupp}, Insn{Code: bpfRetK, K: retAllow}, Insn{Code: bpfRetK, K: retKillProcess}), nil
}
