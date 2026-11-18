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
		script := `SLOW=1 SB=1 ENC=none DRV=" ahci" SER=X TANG_URL=x OUT=/dev/null VM=. BOOT=` + mode + "\n" +
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
