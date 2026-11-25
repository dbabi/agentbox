package gens

import (
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Fuzz targets for what os.apply reads from apt, dpkg, dracut, the kernel and /bootpart (issue #10). CI runs the seeds
// as tests; hack/fuzz-all.sh and the fuzz workflow run them with -fuzz.

func FuzzParseSim(f *testing.F) {
	f.Add([]byte(simOut))
	f.Add([]byte("Purg x [1]\n"))
	f.Add([]byte("Inst a:arm64 [1] (2 o [arm64])\nRemv a:arm64 [1]\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		acts, err := ParseSim(b)
		if err != nil {
			return
		}
		for _, a := range acts {
			if !rePkg.MatchString(a.Package) || (a.Op != "Inst" && a.Op != "Remv") {
				t.Fatalf("accepted %+v", a)
			}
			if a.Op == "Inst" && strings.ContainsAny(DebFile(a), "/ \n") {
				t.Fatalf("deb file name %q", DebFile(a))
			}
		}
	})
}

func FuzzParseURIs(f *testing.F) {
	f.Add([]byte(urisOut))
	f.Add([]byte("'x' a.deb 99999999999999999999 SHA256:00\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		us, err := ParseURIs(b)
		if err != nil {
			return
		}
		for _, u := range us {
			if u.Size < 0 || strings.Contains(u.File, "/") || !strings.HasSuffix(u.File, ".deb") {
				t.Fatalf("accepted %+v", u)
			}
		}
	})
}

// FuzzEndState runs the plan pipeline: a dpkg status file and an apt simulation into the end state.
func FuzzEndState(f *testing.F) {
	f.Add([]byte(statusFixture), []byte(simOut), "arm64")
	f.Add([]byte("Package: a\nStatus: install ok installed\n"), []byte("Remv a\n"), "amd64")
	f.Fuzz(func(t *testing.T, status, sim []byte, native string) {
		inst, err := Installed(status)
		if err != nil {
			return
		}
		acts, err := ParseSim(sim)
		if err != nil {
			return
		}
		end, err := EndState(inst, acts, native)
		if err == nil && !slices.IsSorted(end) {
			t.Fatalf("unsorted end state %q", end)
		}
	})
}

func FuzzLoadPlan(f *testing.F) {
	p := Plan{BaseGen: "gen-1", BaseDpkg: strings.Repeat("a", 64), Request: []string{"x"}, Actions: []Action{{Op: "Inst", Package: "x", Version: "1", Arch: "all"}},
		Debs: []Deb{{File: "x_1_all.deb", Size: 1, SHA256: strings.Repeat("b", 64)}}, EndState: []string{"x:all=1"}}
	f.Add(p.Marshal())
	f.Add([]byte(`{"baseGen":"gen-1","extra":1}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := LoadPlan(b, Hash(b))
		if err != nil {
			return
		}
		if string(got.Marshal()) != string(b) {
			t.Fatalf("accepted a non-canonical plan %q", b)
		}
		if _, err := LoadPlan(b, Hash(append(b, ' '))); err == nil {
			t.Fatal("accepted a plan under another hash")
		}
	})
}

func FuzzRecordedDrivers(f *testing.F) {
	f.Add(`add_drivers+=" nvme nvme_core virtio_blk "`+"\n"+`force_drivers+=" i6300esb "`,
		"kernel/drivers/nvme/host/nvme.ko.zst: kernel/drivers/nvme/host/nvme-core.ko.zst\nkernel/drivers/watchdog/i6300esb.ko.zst:\n",
		"kernel/drivers/block/virtio_blk.ko\n", initrdList, crypttab)
	f.Fuzz(func(t *testing.T, conf, dep, builtin, list, ct string) {
		ds := RecordedDrivers(conf, dep, builtin)
		for _, d := range ds {
			if !strings.Contains(d, ".ko") {
				t.Fatalf("driver file %q", d)
			}
		}
		InitrdProblems(list, ct, Mode{Encrypted: true, Tang: true, Drivers: ds})
	})
}

// FuzzBoot covers what the box reads at boot and commit: the kernel command line, grubenv (on the unencrypted
// /bootpart), grub.cfg, entry ids and boot dir names.
func FuzzBoot(f *testing.F) {
	cfg, err := os.ReadFile("testdata/grub.cfg")
	if err != nil {
		f.Fatal(err)
	}
	f.Add("BOOT_IMAGE=/vmlinuz rootflags=subvol=@gen-12 ro", []byte("# GRUB Environment Block\nsaved_entry=agentbox-gen-3-7.0.0-43-generic\n####"), cfg,
		"agentbox-gen-3-7.0.0-43-generic", "7.0.0-43-generic", "7.0.0-9-generic")
	f.Add("rootflags=subvol=@gen-0", []byte("=\n#=x"), []byte("menuentry 'x' --id '' {"), "agentbox-gen-", "1~rc", "1.a")
	f.Fuzz(func(t *testing.T, cmdline string, env, cfg []byte, id, a, b string) {
		if g, err := CmdlineGen(cmdline); err == nil {
			if _, ok := GenNum(g); !ok {
				t.Fatalf("CmdlineGen gave %q", g)
			}
		}
		GrubEnv(env)
		MenuIDs(cfg)
		CheckEntryArgs(cfg, id, cmdline)
		if g, k, ok := ParseEntry(id); ok && Entry(g, k) != id {
			t.Fatalf("ParseEntry(%q) = %q %q", id, g, k)
		}
		if ab, ba := VerCmp(a, b), VerCmp(b, a); (ab < 0) != (ba > 0) || (ab == 0) != (ba == 0) || VerCmp(a, a) != 0 {
			t.Fatalf("VerCmp(%q, %q) = %d, reversed %d", a, b, ab, ba)
		}
		ks := Kernels([]string{"vmlinuz-" + a, "vmlinuz-" + b, a, "vmlinuz-" + id})
		BadNames(ks)
	})
}

var reCleanPath = regexp.MustCompile(`^/[A-Za-z0-9@._/-]*$`)

func FuzzFstab(f *testing.F) {
	fstab, err := os.ReadFile("testdata/fstab-gen-1")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(fstab, "/.boot/gen-2")
	f.Add([]byte("a /boot x\n# b /boot\nc /boot/ y"), "/x")
	f.Fuzz(func(t *testing.T, fstab []byte, src string) {
		out, err := RewriteBoot(fstab, src)
		if err != nil || !reCleanPath.MatchString(src) || path.Clean(src) != src {
			References(fstab, src)
			return
		}
		if !References(out, src) {
			t.Fatalf("RewriteBoot(%q, %q) = %q, which does not mount it", fstab, src, out)
		}
	})
}
