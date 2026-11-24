//go:build linux && amd64

package seccomp

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// probe386 is a static i386 ELF that calls socketcall(SYS_SOCKET, {AF_VSOCK, SOCK_STREAM, 0}) and exits with the
// negated return: 38 for ENOSYS, 97 for EAFNOSUPPORT, 256-fd for a socket.
func probe386() []byte {
	code := []byte{
		0x6a, 0x00, 0x6a, 0x01, 0x6a, 0x28, // push 0; push SOCK_STREAM; push AF_VSOCK
		0x89, 0xe1, // mov ecx, esp
		0xbb, 0x01, 0x00, 0x00, 0x00, // mov ebx, SYS_SOCKET
		0xb8, 0x66, 0x00, 0x00, 0x00, // mov eax, __NR_socketcall
		0xcd, 0x80, // int 0x80
		0xf7, 0xd8, // neg eax
		0x89, 0xc3, // mov ebx, eax
		0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, __NR_exit
		0xcd, 0x80, // int 0x80
	}
	const base, ehsize, phsize = 0x08048000, 52, 32
	size := uint32(ehsize + phsize + len(code))
	b := []byte{0x7f, 'E', 'L', 'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	le := binary.LittleEndian
	b = le.AppendUint16(b, 2) // ET_EXEC
	b = le.AppendUint16(b, 3) // EM_386
	b = le.AppendUint32(b, 1)
	b = le.AppendUint32(b, base+ehsize+phsize) // entry
	b = le.AppendUint32(b, ehsize)             // phoff
	b = le.AppendUint32(b, 0)                  // shoff
	b = le.AppendUint32(b, 0)                  // flags
	for _, v := range []uint16{ehsize, phsize, 1, 0, 0, 0} {
		b = le.AppendUint16(b, v)
	}
	for _, v := range []uint32{1, 0, base, base, size, size, 5, 0x1000} { // PT_LOAD, R+X
		b = le.AppendUint32(b, v)
	}
	return append(b, code...)
}

// #181: on amd64 a 32-bit socketcall gets no socket under the task profile, while the same probe with seccomp off
// reaches the kernel's socket code. The probe is the whole rootfs, so no image is pulled.
func TestTaskCompatSocketcall(t *testing.T) {
	if _, err := exec.LookPath("podman"); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("CI needs podman")
		}
		t.Skip("podman not installed")
	}
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	prof, err := Task()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "probe"), probe386(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "task.json"), prof, 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(sec string) int {
		t.Helper()
		out, err := exec.Command("podman", "run", "--rm", "--network=none", "--security-opt", "seccomp="+sec, "--rootfs", root, "/probe").CombinedOutput()
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("podman run (seccomp=%s): %v\n%s", sec, err, out)
		}
		t.Logf("seccomp=%s: exit %d %s", sec, ee.ExitCode(), out)
		return ee.ExitCode()
	}
	// a socket fd (256-fd) or EAFNOSUPPORT: socketcall ran. Anything else means this kernel has no IA32 emulation.
	if c := run("unconfined"); c != 97 && (c < 200 || c > 253) {
		t.Fatalf("with seccomp off the probe exits %d: no 32-bit socketcall on this kernel, so the test proves nothing", c)
	}
	// ENOSYS from a filter that knows x86, or SIGSYS (128+31) from the bad-arch action
	if c := run(filepath.Join(dir, "task.json")); c != 38 && c != 159 {
		t.Fatalf("under the task profile the probe exits %d, want ENOSYS (38) or SIGSYS (159)", c)
	}
}
