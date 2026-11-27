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
	"time"
)

// fakeVMNet gives a test checkout a .vm/vmnet newer than hack/vmnet/vmnet.c, so vm.sh does not build it. The fake writes
// its argv to .vm/vmnet.argv and execs the QEMU after "--".
func fakeVMNet(root string) {
	src := filepath.Join(root, "hack", "vmnet", "vmnet.c")
	os.MkdirAll(filepath.Dir(src), 0o755)
	os.WriteFile(src, nil, 0o644)
	old := time.Now().Add(-time.Hour)
	os.Chtimes(src, old, old)
	os.WriteFile(filepath.Join(root, ".vm", "vmnet"),
		[]byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$0.argv\"\nwhile [ \"$1\" != -- ]; do shift; done; shift\nexec \"$@\"\n"), 0o755)
}

// TestVMArgv runs vm.sh boot under dash from a checkout whose path has a space, a comma and glob characters, with fake
// QEMU and swtpm that record their argv: commas are doubled only inside QEMU key=value options, swtpm gets relative
// paths, and each arch gets its machine, firmware, disk bus and TPM device. QEMU runs under vmnet, with its network on fd 3.
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
	fakeVMNet(root)
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
		"stream,id=n0,addr.type=fd,addr.str=3",
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
		// SSH on 127.0.0.1:2222+ID; Tang (7500+ID) and release-serve (7600+ID) the only host ports the guest reaches
		if net, _ := os.ReadFile(filepath.Join(vm, "vmnet.argv")); !strings.HasPrefix(string(net), "2229\n7507\n7607\n--\n"+m.qemu+"\n") {
			t.Errorf("%s vmnet argv:\n%s", m.arch, net)
		}
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

// TestVMInstallPin runs vm.sh install on a stock ISO that does not match hack/SHA256SUMS: with and without DIRECT_KERNEL
// it refuses before it writes any VM state, and once the ISO is pinned it gets past the check. The seed is encrypted, so
// a check moved below tpm.on is caught, and BIOS, so a regression never fetches the UEFI firmware. xorriso, qemu-img and
// QEMU are fakes that fail.
func TestVMInstallPin(t *testing.T) {
	dash, err := exec.LookPath("dash")
	if err != nil {
		t.Skip("dash not installed")
	}
	src, err := os.ReadFile("vm.sh")
	if err != nil {
		t.Fatal(err)
	}
	root, bin, seed := t.TempDir(), t.TempDir(), t.TempDir()
	hack, vm := filepath.Join(root, "hack"), filepath.Join(root, ".vm")
	os.MkdirAll(hack, 0o755)
	os.MkdirAll(vm, 0o755)
	os.WriteFile(filepath.Join(hack, "vm.sh"), src, 0o755)
	iso, junk := "ubuntu-26.04.1-live-server-amd64.iso", []byte("not the pinned ISO\n")
	os.WriteFile(filepath.Join(vm, iso), junk, 0o644)
	os.WriteFile(filepath.Join(seed, "user-data"), []byte("#cloud-config\n#\n# encryption=tpm2 boot=bios\nserial: \"QEMU_HARDDISK_QM00001\"\n"), 0o644)
	os.WriteFile(filepath.Join(seed, "meta-data"), nil, 0o644)
	for _, b := range []string{"xorriso", "qemu-img", "qemu-system-x86_64"} {
		os.WriteFile(filepath.Join(bin, b), []byte("#!/bin/sh\necho fake "+b+" >&2; exit 1\n"), 0o755)
	}
	h := sha256.Sum256(junk)
	good := hex.EncodeToString(h[:])
	for _, pin := range []string{strings.Repeat("0", 64), good} {
		os.WriteFile(filepath.Join(hack, "SHA256SUMS"), []byte(pin+"  "+iso+"\n"), 0o644)
		for _, dk := range []string{"0", "1"} {
			c := exec.Command(dash, filepath.Join(hack, "vm.sh"), "install", seed)
			// set here, so the caller's environment cannot point vm.sh at the real ISO or another disk bus
			c.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "AGENTBOX_ISO_DIR="+vm, "DISKBUS=sata", "DIRECT_KERNEL="+dk)
			out, err := c.CombinedOutput()
			if pin != good {
				if err == nil || !strings.Contains(string(out), iso+" does not match hack/SHA256SUMS") {
					t.Errorf("DIRECT_KERNEL=%s: unpinned ISO not refused: %v\n%s", dk, err, out)
				}
				if left, _ := os.ReadDir(vm); len(left) != 1 {
					t.Errorf("DIRECT_KERNEL=%s: the refusal left VM state in .vm: %v", dk, left)
				}
			} else if !strings.Contains(string(out), "fake xorriso") { // the seed ISO comes next
				t.Errorf("DIRECT_KERNEL=%s: pinned ISO did not get past the check: %v\n%s", dk, err, out)
			}
		}
	}
}

// TestVMFirmwareFallback runs vm.sh install for an arm64 seed with a fake curl for which launchpad.net does not answer:
// fw fetches the AAVMF .deb from the Ubuntu archive pool instead, after launchpad.net, and the install goes on to the
// seed ISO with the three firmware files in .vm/fw. A .deb that fails its pin is refused, and nothing reaches .vm/fw (#307).
func TestVMFirmwareFallback(t *testing.T) {
	dash, err := exec.LookPath("dash")
	if err != nil {
		t.Skip("dash not installed")
	}
	src, err := os.ReadFile("vm.sh")
	if err != nil {
		t.Fatal(err)
	}
	sum := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	fw := map[string]string{"AAVMF_CODE.ms.fd": "code\n", "AAVMF_VARS.ms.fd": "vars-ms\n", "AAVMF_VARS.fd": "vars\n"}
	for _, pinned := range []bool{true, false} {
		root, bin, seed := t.TempDir(), t.TempDir(), t.TempDir()
		hack, vm := filepath.Join(root, "hack"), filepath.Join(root, ".vm")
		os.MkdirAll(hack, 0o755)
		os.MkdirAll(vm, 0o755)
		os.WriteFile(filepath.Join(hack, "vm.sh"), src, 0o755)
		iso := "ubuntu-26.04.1-live-server-arm64.iso"
		os.WriteFile(filepath.Join(vm, iso), []byte("iso\n"), 0o644)
		os.WriteFile(filepath.Join(seed, "user-data"), []byte("#cloud-config\n#\n# encryption=none boot=uefi\nserial: \"QEMU_NVMe_Ctrl_QM00001_1\"\n"), 0o644)
		os.WriteFile(filepath.Join(seed, "meta-data"), nil, 0o644)
		pins := sum("iso\n") + "  " + iso + "\n"
		for f, c := range fw {
			pins += sum(c) + "  " + f + "\n"
		}
		deb := sum("deb\n")
		if !pinned {
			deb = strings.Repeat("0", 64)
		}
		os.WriteFile(filepath.Join(hack, "SHA256SUMS"), []byte(pins+deb+"  qemu-efi-aarch64_2025.11-3ubuntu7.3_all.deb\n"), 0o644)
		fakes := map[string]string{
			// each URL it is asked for goes to $LOG; launchpad.net times out, the archive pool serves the .deb
			"curl": "#!/bin/sh\nwhile [ $# -gt 1 ]; do [ \"$1\" = -o ] && out=$2; shift; done\necho \"$1\" >> \"$LOG\"\n" +
				"case $1 in https://launchpad.net/*) exit 28 ;; http://archive.ubuntu.com/ubuntu/pool/main/e/edk2/*) printf 'deb\\n' > \"$out\" ;; *) exit 22 ;; esac\n",
			"ar":      "#!/bin/sh\n: > data.tar.zst\n",
			"tar":     "#!/bin/sh\nmkdir -p usr/share/AAVMF && cd usr/share/AAVMF && printf 'code\\n' > AAVMF_CODE.ms.fd && printf 'vars-ms\\n' > AAVMF_VARS.ms.fd && printf 'vars\\n' > AAVMF_VARS.fd\n",
			"xorriso": "#!/bin/sh\necho fake xorriso >&2; exit 1\n",
		}
		for b, s := range fakes {
			os.WriteFile(filepath.Join(bin, b), []byte(s), 0o755)
		}
		log := filepath.Join(t.TempDir(), "curl.log")
		c := exec.Command(dash, filepath.Join(hack, "vm.sh"), "install", seed)
		c.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "AGENTBOX_ISO_DIR="+vm, "LOG="+log, "SECUREBOOT=1", "DIRECT_KERNEL=0")
		out, _ := c.CombinedOutput()
		urls, _ := os.ReadFile(log)
		if want := "https://launchpad.net/ubuntu/+archive/primary/+files/qemu-efi-aarch64_2025.11-3ubuntu7.3_all.deb\n" +
			"http://archive.ubuntu.com/ubuntu/pool/main/e/edk2/qemu-efi-aarch64_2025.11-3ubuntu7.3_all.deb\n"; string(urls) != want {
			t.Errorf("pinned=%v: curl was asked for\n%s, want\n%s", pinned, urls, want)
		}
		got, _ := os.ReadDir(filepath.Join(vm, "fw"))
		if pinned {
			if !strings.Contains(string(out), "fake xorriso") || len(got) != len(fw) {
				t.Errorf("the archive's pinned .deb did not get the install to the seed ISO with %d firmware files (%d):\n%s", len(fw), len(got), out)
			}
			for f, want := range fw {
				if b, _ := os.ReadFile(filepath.Join(vm, "fw", f)); string(b) != want {
					t.Errorf(".vm/fw/%s = %q, want %q", f, b, want)
				}
			}
		} else if !strings.Contains(string(out), "qemu-efi-aarch64_2025.11-3ubuntu7.3_all.deb does not match hack/SHA256SUMS") || len(got) != 0 {
			t.Errorf("an unpinned .deb was not refused, or left firmware in .vm/fw (%d files):\n%s", len(got), out)
		}
	}
}

// TestVMInstallSleep runs vm.sh install with a fake clock that jumps 10000 s once, as when the host sleeps: that gap does
// not count against INSTALL_TIMEOUT=100, so the install still finishes, and an installer error after it names the sleep.
// QEMU is a fake that ends the install (or errors) once the clock has been read a set number of times.
func TestVMInstallSleep(t *testing.T) {
	dash, err := exec.LookPath("dash")
	if err != nil {
		t.Skip("dash not installed")
	}
	src, err := os.ReadFile("vm.sh")
	if err != nil {
		t.Fatal(err)
	}
	iso := "ubuntu-26.04.1-live-server-amd64.iso"
	for _, tc := range []struct{ name, line, then, want string }{
		{"finish", "reboot: Restarting system", "", "install ok"},
		{"error", "An error occurred", "exec /bin/sleep 30", "the host slept 10005 s mid-install"}, // subiquity waits at its prompt
	} {
		root, bin, seed := t.TempDir(), t.TempDir(), t.TempDir()
		hack, vm := filepath.Join(root, "hack"), filepath.Join(root, ".vm")
		os.MkdirAll(hack, 0o755)
		os.MkdirAll(vm, 0o755)
		os.WriteFile(filepath.Join(hack, "vm.sh"), src, 0o755)
		fakeVMNet(root)
		os.WriteFile(filepath.Join(vm, iso), []byte("iso\n"), 0o644)
		h := sha256.Sum256([]byte("iso\n"))
		os.WriteFile(filepath.Join(hack, "SHA256SUMS"), []byte(hex.EncodeToString(h[:])+"  "+iso+"\n"), 0o644)
		os.WriteFile(filepath.Join(seed, "user-data"), []byte("#cloud-config\n#\n# encryption=none boot=bios\nserial: \"QEMU_HARDDISK_QM00001\"\n"), 0o644)
		os.WriteFile(filepath.Join(seed, "meta-data"), nil, 0o644)
		n := filepath.Join(bin, "n")
		fakes := map[string]string{
			"xorriso": "exit 0", "qemu-img": "exit 0", "sleep": "exit 0",
			// the 4th read jumps 10000 s; every other read is 5 s after the one before, up to the 15th. After that the clock
			// stands still, so a fast host that spins through extra reads cannot run the 100 s timeout out.
			// the count goes in by rename, so the fake QEMU never reads it half-written (#308)
			"date": `[ "$1" = +%s ] || exec /bin/date "$@"; c=$(cat "` + n + `" 2>/dev/null || echo 0); echo $((c+1)) > "` + n + `.w" && mv "` + n + `.w" "` + n + `"
[ "$c" -gt 14 ] && c=14; [ "$c" -ge 3 ] && echo $((1000 + 5*c + 10000)) || echo $((1000 + 5*c))`,
			// 15 reads: 70 s awake, under INSTALL_TIMEOUT=100 only if the 10000 s jump does not count
			"qemu-system-x86_64": `while [ "$(cat "` + n + `" 2>/dev/null || echo 0)" -lt 15 ]; do /bin/sleep 0.05; done
echo "` + tc.line + `" >> "` + filepath.Join(vm, "install.log") + `"
` + tc.then,
		}
		for b, body := range fakes {
			os.WriteFile(filepath.Join(bin, b), []byte("#!/bin/sh\n"+body+"\n"), 0o755)
		}
		c := exec.Command(dash, filepath.Join(hack, "vm.sh"), "install", seed)
		c.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "AGENTBOX_ISO_DIR="+vm, "DISKBUS=sata",
			"DIRECT_KERNEL=1", "INSTALL_TIMEOUT=100", "AGENTBOX_VM_ID=0")
		out, err := c.CombinedOutput()
		if !strings.Contains(string(out), tc.want) || (err == nil) != (tc.name == "finish") {
			t.Errorf("%s: want %q: %v\n%s", tc.name, tc.want, err, out)
		}
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
