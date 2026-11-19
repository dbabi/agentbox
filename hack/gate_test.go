package hack

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestGateBootMode expands gate.sh's first check block the way the host does, under dash with a fake vm.sh that
// answers with a boot_id: the block must still see the boot mode, so a BIOS gate checks "no EFI" and a UEFI gate
// checks Secure Boot and the kernel signatures. (BOOT once held the boot_id here, and every BIOS gate failed on mokutil.)
func TestGateBootMode(t *testing.T) {
	dash, err := exec.LookPath("dash")
	if err != nil {
		t.Skip("dash not installed")
	}
	src, err := os.ReadFile("gate.sh")
	if err != nil {
		t.Fatal(err)
	}
	// from the boot wait through the first check block, which the host expands and pipes to vmroot
	m := regexp.MustCompile(`(?s)\nbooted\(\) \{.*?\nEOF\n`).Find(src)
	if m == nil {
		t.Fatal("booted() and the first check block not found in gate.sh")
	}
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "hack"), 0o755)
	os.WriteFile(filepath.Join(root, "hack", "vm.sh"), []byte("#!/bin/sh\n[ \"$1\" = ssh ] && echo 6c1f2b9e-4d3a-4c55-9f0e-0a1b2c3d4e5f\n"), 0o755)
	for _, mode := range []string{"bios", "uefi"} {
		block := filepath.Join(root, "block-"+mode)
		script := `SLOW=1 SB=1 ENC=none DRV=" ahci" WD=x WDID=x SER=X TANG_URL=x OUT=/dev/null VM=. BOOT=` + mode + "\n" +
			`die() { echo "$*" >&2; exit 1; }; vmroot() { cat > "` + block + `"; }` + string(m)
		c := exec.Command(dash, "-euc", script)
		c.Dir = root
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", mode, err, out)
		}
		b, _ := os.ReadFile(block)
		for _, want := range []string{`if [ "` + mode + `" = bios ]; then`, `[ "` + mode + `" = bios ] || check "shim accepts every kernel`} {
			if !strings.Contains(string(b), want) {
				t.Errorf("%s: the check block lacks %q", mode, want)
			}
		}
	}
}

// TestGateUnwritten runs gate.sh's dup-serial disk check under dash on real qcow2 images: a fresh image passes, and an
// image the guest wrote fails, a Write Zeroes ("data": false) included, as does one qemu-img can't read.
func TestGateUnwritten(t *testing.T) {
	dash, err := exec.LookPath("dash")
	if err != nil {
		t.Skip("dash not installed")
	}
	for _, b := range []string{"qemu-img", "qemu-io"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skip(b + " not installed")
		}
	}
	src, err := os.ReadFile("gate.sh")
	if err != nil {
		t.Fatal(err)
	}
	loop := regexp.MustCompile(`(?s)\n *for d in disk disk2; do.*?\n *done\n`).Find(src)
	if loop == nil {
		t.Fatal("the dup-serial disk loop not found in gate.sh")
	}
	for _, c := range []struct {
		name, io string // qemu-io command on disk2.qcow2; "" leaves it fresh, "-" removes it
		pass bool
	}{
		{"fresh", "", true},
		{"zero write", "write -z 0 64k", false},
		{"data write of zeros", "write -P 0 0 64k", false},
		{"data write", "write -P 0xab 1M 4k", false},
		{"discard of nothing written", "discard 0 64k", true},
		{"missing", "-", false},
	} {
		dir := t.TempDir()
		for _, d := range []string{"disk", "disk2"} {
			if out, err := exec.Command("qemu-img", "create", "-q", "-f", "qcow2", filepath.Join(dir, d+".qcow2"), "40G").CombinedOutput(); err != nil {
				t.Fatalf("qemu-img create: %v\n%s", err, out)
			}
		}
		switch c.io {
		case "":
		case "-":
			os.Remove(filepath.Join(dir, "disk2.qcow2"))
		default:
			if out, err := exec.Command("qemu-io", "-f", "qcow2", "-c", c.io, filepath.Join(dir, "disk2.qcow2")).CombinedOutput(); err != nil {
				t.Fatalf("qemu-io %s: %v\n%s", c.io, err, out)
			}
		}
		cmd := exec.Command(dash, "-c", "VM=. n=0"+string(loop)+"echo n=$n")
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", c.name, err, out)
		}
		want := "PASS disk2.qcow2 never written"
		if !c.pass {
			want = "FAIL disk2.qcow2 written or unreadable"
		}
		if !strings.Contains(string(out), "PASS disk.qcow2 never written") || !strings.Contains(string(out), want) {
			t.Errorf("%s: want %q\n%s", c.name, want, out)
		}
	}
}
