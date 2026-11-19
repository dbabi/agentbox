package gens

import (
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// apt 3.2.1 output captured on the 26.04.1 arm64 VM (Remv, reinstall, epochs, two origins, the trailing [] form).
const simOut = `NOTE: This is only a simulation!
      apt-get needs root privileges for real execution.
Reading package lists...
Building dependency tree...
The following packages will be upgraded:
  base-files libaudit1 motd-news-config open-iscsi
Inst motd-news-config [14ubuntu6.2] (14ubuntu6.3 Ubuntu:26.04/resolute-updates [all])
Inst base-files [14ubuntu6.2] (14ubuntu6.3 Ubuntu:26.04/resolute-updates [arm64])
Inst open-iscsi [2.1.11-3ubuntu3] (2.1.11-3ubuntu3.1 Ubuntu:26.04/resolute-updates [arm64]) []
Inst libaudit1 [1:4.1.2-1build1] (1:4.1.2-1ubuntu0.1 Ubuntu:26.04/resolute-updates [arm64])
Inst systemd [259.9-0ubuntu0.1] (259.9-0ubuntu0.1 Ubuntu:26.04/resolute-updates [arm64])
Inst linux-generic (7.0.0-43.43 Ubuntu:26.04/resolute-updates, Ubuntu:26.04/resolute-security [arm64])
Conf motd-news-config (14ubuntu6.3 Ubuntu:26.04/resolute-updates [all])
Conf base-files (14ubuntu6.3 Ubuntu:26.04/resolute-updates [arm64])
Remv linux-modules-7.0.0-30-generic [7.0.0-30.30] [linux-image-unsigned-7.0.0-30-generic:arm64 ]
Remv linux-image-unsigned-7.0.0-30-generic [7.0.0-30.30]
`

const urisOut = `'http://us.archive.ubuntu.com/ubuntu/pool/main/b/base-files/motd-news-config_14ubuntu6.3_all.deb' motd-news-config_14ubuntu6.3_all.deb 5286 MD5Sum:744479f8f71413ddc1d51953ee8f4ce0
'http://us.archive.ubuntu.com/ubuntu/pool/main/b/base-files/base-files_14ubuntu6.3_arm64.deb' base-files_14ubuntu6.3_arm64.deb 74862 MD5Sum:5c8532ff6f9e3fc0576f0c88e669306c
'http://us.archive.ubuntu.com/ubuntu/pool/main/a/audit/libaudit1_1%3a4.1.2-1ubuntu0.1_arm64.deb' libaudit1_1%3a4.1.2-1ubuntu0.1_arm64.deb 51234 SHA256:0f87c44ba6294cc786833e8619b996530f87c44ba6294cc786833e8619b99653
`

const statusFixture = `Package: base-files
Essential: yes
Status: install ok installed
Architecture: arm64
Version: 14ubuntu6.2
Conffiles:
 /etc/issue ef8fa0f7f7eff989042ae72c0995820b
Description: Debian base system miscellaneous files

Package: libaudit1
Status: install ok installed
Architecture: arm64
Multi-Arch: same
Version: 1:4.1.2-1build1

Package: motd-news-config
Status: install ok installed
Architecture: all
Version: 14ubuntu6.2

Package: linux-image-unsigned-7.0.0-30-generic
Status: install ok installed
Architecture: arm64
Version: 7.0.0-30.30

Package: linux-modules-7.0.0-30-generic
Status: install ok installed
Architecture: arm64
Version: 7.0.0-30.30

Package: open-iscsi
Status: install ok installed
Architecture: arm64
Version: 2.1.11-3ubuntu3

Package: systemd
Status: install ok installed
Architecture: arm64
Version: 259.9-0ubuntu0.1

Package: kdump-tools
Status: deinstall ok config-files
Architecture: arm64
Version: 1:1.10.5-0ubuntu1
`

func TestParseSim(t *testing.T) {
	acts, err := ParseSim([]byte(simOut))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, a := range acts {
		got = append(got, a.Op+" "+a.Package+" "+a.Old+" "+a.Version+" "+a.Arch)
	}
	want := []string{
		"Inst base-files 14ubuntu6.2 14ubuntu6.3 arm64",
		"Inst libaudit1 1:4.1.2-1build1 1:4.1.2-1ubuntu0.1 arm64",
		"Inst linux-generic  7.0.0-43.43 arm64",
		"Remv linux-image-unsigned-7.0.0-30-generic 7.0.0-30.30  ",
		"Remv linux-modules-7.0.0-30-generic 7.0.0-30.30  ",
		"Inst motd-news-config 14ubuntu6.2 14ubuntu6.3 all",
		"Inst open-iscsi 2.1.11-3ubuntu3 2.1.11-3ubuntu3.1 arm64",
		"Inst systemd 259.9-0ubuntu0.1 259.9-0ubuntu0.1 arm64",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("ParseSim:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if acts[2].Origin != "Ubuntu:26.04/resolute-updates, Ubuntu:26.04/resolute-security" {
		t.Errorf("origin %q", acts[2].Origin)
	}
	for _, bad := range []string{
		"Purg kdump-tools [1:1.10.5-0ubuntu1]",                // week-1 plans never purge
		"Inst systemd (259.9 garbled",                         // an Inst line we can't read
		"Inst Bad_Name [1] (2 Ubuntu:26.04/resolute [arm64])", // not a Debian package name
		"Inst x11 [1] (2;id Ubuntu:26.04/resolute [arm64])",   // not a version
	} {
		if _, err := ParseSim([]byte(bad + "\n")); err == nil {
			t.Errorf("ParseSim accepted %q", bad)
		}
	}
}

func TestParseURIs(t *testing.T) {
	us, err := ParseURIs([]byte(urisOut))
	if err != nil {
		t.Fatal(err)
	}
	if len(us) != 3 || us[0].File != "motd-news-config_14ubuntu6.3_all.deb" || us[0].Size != 5286 || us[0].HashType != "MD5Sum" ||
		us[2].HashType != "SHA256" || us[2].File != "libaudit1_1%3a4.1.2-1ubuntu0.1_arm64.deb" {
		t.Fatalf("ParseURIs = %+v", us)
	}
	for _, bad := range []string{
		"'http://x/a.deb' ../../etc/passwd 1 MD5Sum:00",       // a path, not a file name
		"'http://x/a.deb' a_1_all.deb 12 CRC32:deadbeef",      // unknown hash
		"'http://x/a.deb' a_1_all.deb twelve MD5Sum:deadbeef", // size
	} {
		if _, err := ParseURIs([]byte(bad)); err == nil {
			t.Errorf("ParseURIs accepted %q", bad)
		}
	}
	if f := DebFile(Action{Op: "Inst", Package: "libaudit1", Version: "1:4.1.2-1ubuntu0.1", Arch: "arm64"}); f != us[2].File {
		t.Errorf("DebFile = %q, want apt's %q", f, us[2].File)
	}
}

func TestEndState(t *testing.T) {
	inst, err := Installed([]byte(statusFixture))
	if err != nil {
		t.Fatal(err)
	}
	if len(inst) != 7 || inst["libaudit1:arm64"] != "1:4.1.2-1build1" || inst["motd-news-config:all"] != "14ubuntu6.2" {
		t.Fatalf("Installed = %v (config-files packages are not installed)", inst)
	}
	acts, _ := ParseSim([]byte(simOut))
	end, err := EndState(inst, acts, "arm64")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"base-files:arm64=14ubuntu6.3", "libaudit1:arm64=1:4.1.2-1ubuntu0.1", "linux-generic:arm64=7.0.0-43.43",
		"motd-news-config:all=14ubuntu6.3", "open-iscsi:arm64=2.1.11-3ubuntu3.1", "systemd:arm64=259.9-0ubuntu0.1"}
	if !slices.Equal(end, want) {
		t.Fatalf("EndState = %v\nwant %v", end, want)
	}
	two := map[string]string{"libfoo:arm64": "1", "libfoo:armhf": "1"}
	if _, err := EndState(two, []Action{{Op: "Remv", Package: "libfoo"}}, "arm64"); err == nil {
		t.Error("an ambiguous multi-arch removal was accepted")
	}
	if end, err := EndState(two, []Action{{Op: "Remv", Package: "libfoo:armhf"}}, "arm64"); err != nil || !slices.Equal(end, []string{"libfoo:arm64=1"}) {
		t.Errorf("arch-qualified removal: %v %v", end, err)
	}
	// apt 3.2 on resolute arm64, crossgrades in the native slot (verify-gens-endstate-arch/real-sim.txt): dpkg keeps
	// only the new instance; the Multi-Arch: same foreign one is its own slot
	cross, err := ParseSim([]byte(`Inst bar [1.0] (2.0 localhost [all])
Inst foo [1.0] (2.0 localhost [arm64])
Inst libm [1.0] (2.0 localhost [arm64]) [libm:arm64 on libm:armhf] [libm:armhf on libm:arm64] [libm:armhf ]
Inst libm:armhf [1.0] (2.0 localhost [armhf])
`))
	if err != nil {
		t.Fatal(err)
	}
	before := map[string]string{"bar:arm64": "1.0", "foo:all": "1.0", "libm:arm64": "1.0", "libm:armhf": "1.0", "libx:armhf": "1"}
	want = []string{"bar:all=2.0", "foo:arm64=2.0", "libm:arm64=2.0", "libm:armhf=2.0", "libx:armhf=1"}
	if end, err := EndState(before, cross, "arm64"); err != nil || !slices.Equal(end, want) {
		t.Errorf("crossgrade: %v %v, want %v", end, err, want)
	}
}

// TestPrint feeds the approval listing origins with terminal controls, bidi and invisible characters: they are repo
// Release text, and must reach the human only as printable characters (§5.4).
func TestPrint(t *testing.T) {
	for _, o := range []string{"Ubuntu:26.04/resolute-updates, Ubuntu:26.04/resolute-security", "Café",
		"resolute-security\x1b[2K\rInst base-files 1 -> 2 [all] (Ubuntu:26.04/resolute-updates", "a\u009b2Kb",
		"a\u202eb", "a\u2066b\u2069", "a\u200bb", "a\u2028b", "a\ufeffb", "a\U000e0001b", "a\u00a0b", "a\xffb"} {
		for _, l := range []string{"Inst x11 [1] (2 " + o + " [arm64])", "Inst x11 (2 " + o + " [arm64])"} {
			acts, err := ParseSim([]byte(l + "\n"))
			if err != nil || len(acts) != 1 || acts[0].Origin != o {
				t.Fatalf("ParseSim(%q) = %+v, %v", l, acts, err)
			}
			out := (&Plan{BaseGen: "gen-1", Actions: acts}).Print(strings.Repeat("0", 64))
			for _, r := range out {
				if r != '\n' && !unicode.IsPrint(r) {
					t.Errorf("origin %q: the listing has %U", o, r)
				}
			}
			if !strings.Contains(out, "("+strconv.Quote(o)+")") {
				t.Errorf("origin %q is not shown quoted:\n%s", o, out)
			}
		}
	}
}

func TestPlanHash(t *testing.T) {
	acts, _ := ParseSim([]byte(simOut))
	p := &Plan{BaseGen: "gen-1", BaseDpkg: Hash([]byte(statusFixture)), Request: []string{"--reinstall", "systemd"},
		Actions: acts, Debs: []Deb{{File: "base-files_14ubuntu6.3_arm64.deb", Size: 74862, SHA256: strings.Repeat("a", 64)}},
		EndState: []string{"systemd:arm64=259.9-0ubuntu0.1"}}
	b := p.Marshal()
	h := Hash(b)
	if string(p.Marshal()) != string(b) {
		t.Fatal("Marshal is not deterministic")
	}
	q, err := LoadPlan(b, h)
	if err != nil || q.BaseGen != "gen-1" || len(q.Actions) != len(acts) {
		t.Fatalf("LoadPlan: %v", err)
	}
	if _, err := LoadPlan(b, strings.Repeat("0", 64)); err == nil {
		t.Error("LoadPlan accepted a plan that does not hash to the approval")
	}
	for _, bad := range [][]byte{
		[]byte(strings.Replace(string(b), "  ", "   ", 1)),                          // same content, other bytes
		[]byte(strings.Replace(string(b), `"baseGen"`, `"extra": 1, "baseGen"`, 1)), // a field the binary would ignore
	} {
		if _, err := LoadPlan(bad, Hash(bad)); err == nil {
			t.Errorf("LoadPlan accepted a non-canonical plan:\n%s", bad)
		}
	}
	args := q.AptArgs()
	if args[0] != "--reinstall" || !slices.Contains(args, "systemd=259.9-0ubuntu0.1") || !slices.Contains(args, "linux-image-unsigned-7.0.0-30-generic-") ||
		!slices.Contains(args, "libaudit1=1:4.1.2-1ubuntu0.1") || len(args) != len(acts)+1 {
		t.Fatalf("AptArgs = %v", args)
	}
	p.Actions = acts[:2]
	if (&Plan{Actions: acts[:2]}).AptArgs()[0] == "--reinstall" {
		t.Error("--reinstall without a reinstall")
	}
	inner := slices.Clone(acts)
	inner[0].Old, inner[0].Origin = "", "elsewhere"
	if !SameActions(inner, acts) {
		t.Error("SameActions must ignore old versions and origins")
	}
	inner[0].Version = "14ubuntu6.4"
	if SameActions(inner, acts) || SameActions(acts[1:], acts) {
		t.Error("SameActions accepted a different closure")
	}
}
