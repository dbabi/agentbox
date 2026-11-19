package hack

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestVMArgv runs vm.sh boot under dash from a checkout whose path has a space, a comma and glob characters, with fake
// QEMU and swtpm that record their argv: commas are doubled only inside QEMU key=value options, swtpm gets relative
// paths, and each arch gets its machine, firmware, disk bus and TPM device.
// The checkout also has a DUP_DISK second disk, so the same-serial NVMe controller args are checked too, and
// AGENTBOX_BLKLOG logs the disk through blklogwrites.
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
	// Each fake writes its working directory, then one argument per line.
	for _, b := range []string{"qemu-system-aarch64", "qemu-system-x86_64", "swtpm"} {
		os.WriteFile(filepath.Join(bin, b), []byte("#!/bin/sh\n{ pwd; printf '%s\\n' \"$@\"; } > \"$0.argv\"\n"), 0o755)
	}
	boot := func(id, blklog string) ([]byte, error) {
		c := exec.Command(dash, filepath.Join(root, "hack", "vm.sh"), "boot")
		c.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "AGENTBOX_VM_ID="+id, "AGENTBOX_BLKLOG="+blklog)
		return c.CombinedOutput()
	}
	argv := func(b string) []string {
		out, err := os.ReadFile(filepath.Join(bin, b+".argv"))
		if err != nil {
			t.Fatal(err)
		}
		return strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	}
	if out, err := boot("7", ""); err == nil || !strings.Contains(string(out), "predates the pinned firmware") {
		t.Errorf("boot without .vm/arch: %v\n%s", err, out)
	}
	q := strings.ReplaceAll(vm, ",", ",,")
	common := []string{
		"if=none,id=d0,format=qcow2,file=" + q + "/disk.qcow2",
		"user,id=n0,hostfwd=tcp:127.0.0.1:2229-:22",
		"unix:" + q + "/qmp.sock,server=on,wait=off",
		"socket,id=chrtpm,path=" + q + "/tpm/sock",
		vm + "/qemu.pid",
	}
	for _, m := range []struct {
		arch, bus, qemu string
		want            []string
	}{
		{"arm64", "nvme", "qemu-system-aarch64", []string{"virt-11.0", "hvf", "if=pflash,format=raw,readonly=on,file=" + q + "/fw/AAVMF_CODE.ms.fd",
			"if=pflash,format=raw,file=" + q + "/vars.fd", "nvme,drive=d0,serial=QM00001", "tpm-tis-device,tpmdev=tpm0,ppi=off",
			"nvme,id=dupctl,serial=QM00001,subsys=dupsys", "if=none,id=d1,format=qcow2,file=" + q + "/disk2.qcow2"}},
		{"amd64", "sata", "qemu-system-x86_64", []string{"q35", "tcg", "ide-hd,bus=ide.0,drive=d0,serial=QM00001", "tpm-tis,tpmdev=tpm0"}},
	} {
		os.WriteFile(filepath.Join(vm, "arch"), []byte(m.arch+"\n"), 0o644)
		os.WriteFile(filepath.Join(vm, "diskbus"), []byte(m.bus+"\n"), 0o644)
		if out, err := boot("7", ""); err != nil {
			t.Fatalf("vm.sh boot (%s): %v\n%s", m.arch, err, out)
		}
		qemu := argv(m.qemu)[1:]
		for _, want := range slices.Concat(common, m.want) {
			if !slices.Contains(qemu, want) {
				t.Errorf("%s QEMU argv lacks %q:\n%s", m.arch, want, strings.Join(qemu, "\n"))
			}
		}
		if wd := slices.Contains(qemu, "i6300esb"); wd != (m.arch == "amd64") { // arm64 virt boots the softdog fallback
			t.Errorf("%s QEMU argv has an i6300esb: %v, want %v", m.arch, wd, m.arch == "amd64")
		}
		if pf := slices.ContainsFunc(qemu, func(s string) bool { return strings.HasPrefix(s, "if=pflash") }); pf != (m.arch == "arm64") {
			t.Errorf("%s QEMU argv has pflash drives: %v, want %v", m.arch, pf, m.arch == "arm64")
		}
		if s := strings.Join(qemu[len(qemu)-4:], " "); !strings.HasPrefix(s, "-chardev socket,id=con,path="+q+"/console.sock,server=on,wait=off,logfile="+q+"/boot-") ||
			!strings.HasSuffix(s, ".log -serial chardev:con") {
			t.Errorf("%s console %q, want a socket chardev that logs to boot-*.log", m.arch, s)
		}
	}
	sw := argv("swtpm")
	if !strings.HasSuffix(sw[0], "/a b,c*[d]/.vm/tpm") ||
		strings.Join(sw[1:], " ") != "socket --tpm2 --tpmstate dir=. --ctrl type=unixio,path=sock,terminate --pid file=pid --daemon" {
		t.Errorf("swtpm ran as %q", sw)
	}
	// AGENTBOX_BLKLOG puts QEMU's blklogwrites driver between the device and the qcow2 disk
	os.WriteFile(filepath.Join(vm, "arch"), []byte("arm64\n"), 0o644)
	os.WriteFile(filepath.Join(vm, "diskbus"), []byte("nvme\n"), 0o644)
	blklog := filepath.Join(root, "log,1.bin")
	if out, err := boot("7", blklog); err != nil {
		t.Fatalf("vm.sh boot with AGENTBOX_BLKLOG: %v\n%s", err, out)
	}
	want := "if=none,id=d0,driver=blklogwrites,file.driver=qcow2,file.file.filename=" + q + "/disk.qcow2," +
		"log.driver=file,log.filename=" + strings.ReplaceAll(blklog, ",", ",,")
	if qemu := argv("qemu-system-aarch64")[1:]; !slices.Contains(qemu, want) {
		t.Errorf("QEMU argv lacks %q:\n%s", want, strings.Join(qemu, "\n"))
	}
	if out, err := boot("10", ""); err == nil || !strings.Contains(string(out), "AGENTBOX_VM_ID must be 0-9") {
		t.Errorf("AGENTBOX_VM_ID=10 accepted: %v\n%s", err, out)
	}
}

// TestRemasterISO runs remaster-iso.sh on a small ISO with the stock grub.cfg shapes (arm64's `$cmdline  ---  console=tty0`,
// amd64's trailing `--- `, a tab, a non-casper line): every casper linux line gets `autoinstall ds=nocloud` before ` ---`
// and the extra args at the end, /md5sum.txt follows, and an unpinned ISO or unsafe extra args are refused.
func TestRemasterISO(t *testing.T) {
	dash, err := exec.LookPath("dash")
	if err != nil {
		t.Skip("dash not installed")
	}
	if _, err := exec.LookPath("xorriso"); err != nil {
		t.Skip("xorriso not installed")
	}
	src, err := os.ReadFile("remaster-iso.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	hack, tree := filepath.Join(dir, "hack"), filepath.Join(dir, "tree")
	os.MkdirAll(hack, 0o755)
	os.MkdirAll(filepath.Join(tree, "boot", "grub"), 0o755)
	os.WriteFile(filepath.Join(hack, "remaster-iso.sh"), src, 0o755)
	stock := "set timeout=30\nmenuentry \"Try or Install Ubuntu Server\" {\n" +
		"    linux  /casper/vmlinuz $cmdline  ---  console=tty0\n    initrd /casper/initrd\n}\n" +
		"menuentry \"HWE\" {\n\tlinux\t/casper/hwe-vmlinuz  --- \n}\nmenuentry 'Test memory' {\n    linux16 /boot/memtest86+x64.bin\n}\n"
	want := "set timeout=30\nmenuentry \"Try or Install Ubuntu Server\" {\n" +
		"    linux  /casper/vmlinuz $cmdline  autoinstall ds=nocloud ---  console=tty0 console=ttyS0\n    initrd /casper/initrd\n}\n" +
		"menuentry \"HWE\" {\n\tlinux\t/casper/hwe-vmlinuz  autoinstall ds=nocloud --- console=ttyS0\n}\nmenuentry 'Test memory' {\n    linux16 /boot/memtest86+x64.bin\n}\n"
	sum := func(b []byte) string { s := md5.Sum(b); return hex.EncodeToString(s[:]) }
	md5txt := func(cfg string) string {
		return sum([]byte("x")) + "  ./casper/x\n" + sum([]byte(cfg)) + "  ./boot/grub/grub.cfg\n"
	}
	os.WriteFile(filepath.Join(tree, "boot", "grub", "grub.cfg"), []byte(stock), 0o644)
	os.WriteFile(filepath.Join(tree, "md5sum.txt"), []byte(md5txt(stock)), 0o644)
	iso := filepath.Join(dir, "stock.iso")
	if out, err := exec.Command("xorriso", "-as", "mkisofs", "-quiet", "-o", iso, "-V", "stock", "-J", "-r", tree).CombinedOutput(); err != nil {
		t.Fatalf("xorriso: %v\n%s", err, out)
	}
	b, _ := os.ReadFile(iso)
	h := sha256.Sum256(b)
	pin := func(name string) {
		os.WriteFile(filepath.Join(hack, "SHA256SUMS"), []byte(hex.EncodeToString(h[:])+"  "+name+"\n"), 0o644)
	}
	run := func(args ...string) ([]byte, error) {
		return exec.Command(dash, append([]string{filepath.Join(hack, "remaster-iso.sh")}, args...)...).CombinedOutput()
	}
	out := filepath.Join(dir, "out.iso")
	pin("other.iso")
	if o, err := run(iso, out); err == nil || !strings.Contains(string(o), "no pin for stock.iso") {
		t.Errorf("unpinned ISO accepted: %v\n%s", err, o)
	}
	pin("stock.iso")
	if o, err := run(iso, out, "console=ttyS0;reboot"); err == nil || !strings.Contains(string(o), "extra kernel args may use only") {
		t.Errorf("unsafe extra args accepted: %v\n%s", err, o)
	}
	if o, err := run(iso, out, "console=ttyS0"); err != nil {
		t.Fatalf("remaster-iso.sh: %v\n%s", err, o)
	}
	cfg, md := filepath.Join(dir, "grub.cfg"), filepath.Join(dir, "md5sum.txt") // flat: the ISO's directories are read-only
	if o, err := exec.Command("xorriso", "-osirrox", "on", "-indev", out, "-extract", "/boot/grub/grub.cfg", cfg,
		"-extract", "/md5sum.txt", md).CombinedOutput(); err != nil {
		t.Fatalf("xorriso extract: %v\n%s", err, o)
	}
	if got, _ := os.ReadFile(cfg); string(got) != want {
		t.Errorf("grub.cfg:\n%s\nwant:\n%s", got, want)
	}
	if got, _ := os.ReadFile(md); string(got) != md5txt(want) {
		t.Errorf("md5sum.txt:\n%s\nwant:\n%s", got, md5txt(want))
	}
}
