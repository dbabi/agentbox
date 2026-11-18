package hack

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestPowercutBoot runs powercut.sh boot under dash with fake podman and vm.sh. The disk the logged run left is set
// aside while each replayed image boots, and it is back in place whether the checks pass, fail or the replay fails.
func TestPowercutBoot(t *testing.T) {
	dash, err := exec.LookPath("dash")
	if err != nil {
		t.Skip("dash not installed")
	}
	src, err := os.ReadFile("powercut.sh")
	if err != nil {
		t.Fatal(err)
	}
	root, bin, tmp := t.TempDir(), t.TempDir(), t.TempDir()
	vm, pc := filepath.Join(root, ".vm"), filepath.Join(tmp, "agentbox-powercut-3")
	for _, d := range []string{filepath.Join(root, "hack", "powercut"), vm, pc} {
		os.MkdirAll(d, 0o755)
	}
	os.WriteFile(filepath.Join(root, "hack", "powercut.sh"), src, 0o755)
	os.WriteFile(filepath.Join(root, "hack", "powercut", "replay.sh"), nil, 0o644)
	os.WriteFile(filepath.Join(pc, "log.bin"), nil, 0o644)
	os.WriteFile(filepath.Join(pc, "base.qcow2"), nil, 0o644)
	// podman run ... image <entry>: write the replayed image and the entry GRUB boots on it, into the dir mounted at /w
	os.WriteFile(filepath.Join(bin, "podman"), []byte(`#!/bin/sh
case " $* " in *" run "*" image "*) ;; *) exit 0 ;; esac
[ -z "$FAIL_REPLAY" ] || exit 1
for a; do case $a in *:/w) w=${a%:/w} ;; esac; done
echo image > "$w/image.qcow2"; echo "$WANT saved_entry" > "$w/image.expect"
`), 0o755)
	// vm.sh boot records the disk it got and runs until poweroff; vm.sh ssh answers for the VM
	os.WriteFile(filepath.Join(root, "hack", "vm.sh"), []byte(`#!/bin/sh
VM=$(cd "$(dirname "$0")/../.vm" && pwd)
case $1 in
boot) readlink "$VM/disk.qcow2" >> "$VM/booted"; until [ -e "$VM/off" ]; do sleep 0.1; done; rm "$VM/off" ;;
ssh) [ "$2" = true ] && exit 0; s=$(cat); case $s in *poweroff*) touch "$VM/off" ;; *) printf '%b\n' "$CHECKS" ;; esac ;;
esac
`), 0o755)
	run := func(env ...string) (string, error) {
		os.WriteFile(filepath.Join(vm, "disk.qcow2"), []byte("run disk"), 0o644)
		os.Remove(filepath.Join(vm, "booted"))
		c := exec.Command(dash, filepath.Join(root, "hack", "powercut.sh"), "boot", "7", "9")
		c.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TMPDIR="+tmp, "AGENTBOX_VM_ID=3",
			"WANT=agentbox-gen-1-7.0.0-43-generic", "CHECKS=PASS boots\\nfails=0", "FAIL_REPLAY=")
		c.Env = append(c.Env, env...)
		out, err := c.CombinedOutput()
		if b, _ := os.ReadFile(filepath.Join(vm, "disk.qcow2")); string(b) != "run disk" {
			t.Errorf("the run's disk is not back in place: %q", b)
		}
		if fi, err := os.Lstat(filepath.Join(vm, "disk.qcow2")); err != nil || fi.Mode()&os.ModeSymlink != 0 {
			t.Errorf("disk.qcow2 after boot: %v %v", fi, err)
		}
		for _, f := range []string{filepath.Join(vm, "disk.qcow2.powercut"), filepath.Join(pc, "image.qcow2")} {
			if _, err := os.Stat(f); err == nil {
				t.Errorf("%s left behind", f)
			}
		}
		return string(out), err
	}

	out, err := run()
	booted, _ := os.ReadFile(filepath.Join(vm, "booted"))
	if err != nil || !strings.Contains(out, "boot: 2 entries, 0 failed") ||
		string(booted) != strings.Repeat(filepath.Join(pc, "image.qcow2")+"\n", 2) {
		t.Errorf("passing boot: %v, booted %q\n%s", err, booted, out)
	}
	if out, err := run("CHECKS=FAIL boots\\nfails=1"); err == nil || !strings.Contains(out, "boot: 2 entries, 2 failed") {
		t.Errorf("failing checks accepted: %v\n%s", err, out)
	}
	if out, err := run("CHECKS=ssh: connect refused"); err == nil || !strings.Contains(out, "entry 7: FAIL no SSH") {
		t.Errorf("a VM with no SSH accepted: %v\n%s", err, out)
	}
	if out, err := run("WANT=agentbox-gen-1-$(reboot)"); err == nil || !strings.Contains(out, "names no valid entry") {
		t.Errorf("an entry name with shell syntax accepted: %v\n%s", err, out)
	}
	if out, err := run("FAIL_REPLAY=1"); err == nil {
		t.Errorf("a failed replay accepted:\n%s", out)
	}
	// a disk that a killed run set aside is never overwritten
	os.WriteFile(filepath.Join(vm, "disk.qcow2.powercut"), []byte("set aside"), 0o644)
	c := exec.Command(dash, filepath.Join(root, "hack", "powercut.sh"), "boot", "7")
	c.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TMPDIR="+tmp, "AGENTBOX_VM_ID=3")
	if out, err := c.CombinedOutput(); err == nil || !strings.Contains(string(out), "move it back") {
		t.Errorf("boot ran over a set-aside disk: %v\n%s", err, out)
	}
	if b, _ := os.ReadFile(filepath.Join(vm, "disk.qcow2.powercut")); string(b) != "set aside" {
		t.Errorf("set-aside disk changed: %q", b)
	}
	for _, args := range [][]string{{"boot", "7x"}, {"check", "0", "10", "0"}, {"grub", "0", "1x"}} {
		c := exec.Command(dash, append([]string{filepath.Join(root, "hack", "powercut.sh")}, args...)...)
		c.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TMPDIR="+tmp, "AGENTBOX_VM_ID=3")
		if out, err := c.CombinedOutput(); err == nil {
			t.Errorf("powercut.sh %v accepted:\n%s", args, out)
		}
	}
}
