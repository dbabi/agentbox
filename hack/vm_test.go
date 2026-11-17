package hack

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestVMArgv runs vm.sh boot under dash from a checkout whose path has a space, a comma and glob characters, with fake
// QEMU and swtpm that record their argv: commas are doubled only inside QEMU key=value options, swtpm gets relative paths.
// The checkout also has a DUP_DISK second disk, so its same-serial NVMe controller args are checked too.
func TestVMArgv(t *testing.T) {
	dash, err := exec.LookPath("dash")
	if err != nil {
		t.Skip("dash not installed")
	}
	src, err := os.ReadFile("vm.sh")
	if err != nil {
		t.Fatal(err)
	}
	root, bin := filepath.Join(t.TempDir(), "a b,c*[d]"), t.TempDir()
	vm := filepath.Join(root, ".vm")
	os.MkdirAll(filepath.Join(root, "hack"), 0o755)
	os.MkdirAll(vm, 0o755)
	os.WriteFile(filepath.Join(root, "hack", "vm.sh"), src, 0o755)
	os.WriteFile(filepath.Join(vm, "disk.qcow2"), nil, 0o644)
	os.WriteFile(filepath.Join(vm, "disk2.qcow2"), nil, 0o644) // DUP_DISK=1: a second disk with the same serial
	os.WriteFile(filepath.Join(vm, "tpm.on"), nil, 0o644)
	os.WriteFile(filepath.Join(vm, "diskbus"), []byte("nvme\n"), 0o644)
	// Each fake writes its working directory, then one argument per line.
	for _, b := range []string{"qemu-system-aarch64", "swtpm"} {
		os.WriteFile(filepath.Join(bin, b), []byte("#!/bin/sh\n{ pwd; printf '%s\\n' \"$@\"; } > \"$0.argv\"\n"), 0o755)
	}
	boot := func(id string) ([]byte, error) {
		c := exec.Command(dash, filepath.Join(root, "hack", "vm.sh"), "boot")
		c.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "AGENTBOX_VM_ID="+id)
		return c.CombinedOutput()
	}
	argv := func(b string) []string {
		out, err := os.ReadFile(filepath.Join(bin, b+".argv"))
		if err != nil {
			t.Fatal(err)
		}
		return strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	}
	if out, err := boot("7"); err != nil {
		t.Fatalf("vm.sh boot: %v\n%s", err, out)
	}
	q, qemu := strings.ReplaceAll(vm, ",", ",,"), argv("qemu-system-aarch64")[1:]
	for _, want := range []string{
		"if=pflash,format=raw,file=" + q + "/vars.fd",
		"if=none,id=d0,format=qcow2,file=" + q + "/disk.qcow2",
		"nvme,drive=d0,serial=QM00001",
		"nvme,id=dupctl,serial=QM00001,subsys=dupsys",
		"if=none,id=d1,format=qcow2,file=" + q + "/disk2.qcow2",
		"user,id=n0,hostfwd=tcp:127.0.0.1:2229-:22",
		"unix:" + q + "/qmp.sock,server=on,wait=off",
		"socket,id=chrtpm,path=" + q + "/tpm/sock",
		vm + "/qemu.pid",
	} {
		if !slices.Contains(qemu, want) {
			t.Errorf("QEMU argv lacks %q:\n%s", want, strings.Join(qemu, "\n"))
		}
	}
	if s := strings.Join(qemu[len(qemu)-4:], " "); !strings.HasPrefix(s, "-chardev socket,id=con,path="+q+"/console.sock,server=on,wait=off,logfile="+q+"/boot-") ||
		!strings.HasSuffix(s, ".log -serial chardev:con") {
		t.Errorf("console %q, want a socket chardev that logs to boot-*.log", s)
	}
	sw := argv("swtpm")
	if !strings.HasSuffix(sw[0], "/a b,c*[d]/.vm/tpm") ||
		strings.Join(sw[1:], " ") != "socket --tpm2 --tpmstate dir=. --ctrl type=unixio,path=sock,terminate --pid file=pid --daemon" {
		t.Errorf("swtpm ran as %q", sw)
	}
	if out, err := boot("10"); err == nil || !strings.Contains(string(out), "AGENTBOX_VM_ID must be 0-9") {
		t.Errorf("AGENTBOX_VM_ID=10 accepted: %v\n%s", err, out)
	}
}
