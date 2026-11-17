package gens

import (
	"os"
	"strings"
	"testing"
)

func TestRewriteBoot(t *testing.T) {
	gen1, err := os.ReadFile("testdata/fstab-gen-1")
	if err != nil {
		t.Fatal(err)
	}
	got, err := RewriteBoot(gen1, "/bootpart/agentbox/gens/gen-2")
	if err != nil {
		t.Fatal(err)
	}
	// exactly the /boot line changes, and only its source
	a, b := strings.Split(string(gen1), "\n"), strings.Split(string(got), "\n")
	if len(a) != len(b) {
		t.Fatalf("line count %d -> %d", len(a), len(b))
	}
	changed := 0
	for i := range a {
		if a[i] != b[i] {
			changed++
			if b[i] != "/bootpart/agentbox/gens/gen-2 /boot none bind,x-systemd.requires-mounts-for=/bootpart 0 0" {
				t.Errorf("rewritten line %q", b[i])
			}
		}
	}
	if changed != 1 {
		t.Fatalf("%d lines changed, want 1", changed)
	}
	if !References(got, "/bootpart/agentbox/gens/gen-2") || References(got, "/bootpart/agentbox/gens/gen-1") {
		t.Error("References disagrees with the rewrite")
	}
	if References(gen1, "/bootpart/agentbox/gens/gen-10") || !References([]byte("/bootpart/agentbox/gens/gen-1/ /boot none bind 0 0\n"), "/bootpart/agentbox/gens/gen-1") {
		t.Error("References must compare whole paths")
	}

	tabs := "UUID=a\t/\tbtrfs\tdefaults\t0 1\n\t/bootpart/agentbox/gens/gen-7\t/boot/\tnone\tbind\t0 0\n"
	if got, err := RewriteBoot([]byte(tabs), "/bootpart/agentbox/gens/gen-8"); err != nil || string(got) != "UUID=a\t/\tbtrfs\tdefaults\t0 1\n\t/bootpart/agentbox/gens/gen-8\t/boot/\tnone\tbind\t0 0\n" {
		t.Errorf("tab-separated fstab: %q, %v", got, err)
	}
	for name, bad := range map[string]string{
		"no /boot line":          "UUID=a / btrfs defaults 0 1\n/bootpart/grub /boot/grub none bind 0 0\n",
		"two /boot lines":        string(gen1) + "/bootpart/agentbox/gens/gen-1 /boot none bind 0 0\n",
		"only a comment":         "# /bootpart/agentbox/gens/gen-1 /boot none bind 0 0\n",
		"commented out":          "#/bootpart/agentbox/gens/gen-1 /boot none bind 0 0\n",
		"empty fstab":            "",
		"/boot/efi is not /boot": "UUID=E /boot/efi vfat umask=0077 0 1\n",
	} {
		if _, err := RewriteBoot([]byte(bad), "/bootpart/agentbox/gens/gen-2"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
