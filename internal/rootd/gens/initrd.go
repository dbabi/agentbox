package gens

import (
	"path"
	"regexp"
	"strings"
)

// Mode is what the initrd gate requires of every initrd in a new generation (§3.3 step 4).
type Mode struct {
	Encrypted bool     // root on LUKS (crypttab has croot)
	Tang      bool     // the clevis binding has a tang pin, under sss with the tpm2 pin (tpm2+tang mode)
	Drivers   []string // add_drivers and force_drivers recorded at install, unless built into this kernel (file base names)
}

// InitrdProblems returns what one initrd lacks, given `lsinitrd` (its file list) and `lsinitrd -f etc/crypttab`.
func InitrdProblems(list, crypttab string, m Mode) []string {
	var miss []string
	need := []string{"btrfs.ko"}
	if m.Encrypted {
		if !hasLinePrefix(crypttab, "croot ") {
			miss = append(miss, "etc/crypttab has no croot line")
		}
		// both encrypted modes bind a tpm2 pin: alone, or with a tang pin under sss
		need = append(need, "clevis-luks-askpass", "systemd-cryptsetup", "clevis-decrypt-tpm2")
	}
	if m.Tang {
		need = append(need, "clevis-decrypt-sss", "clevis-decrypt-tang")
	}
	need = append(need, m.Drivers...)
	have := initrdFiles(list)
	for _, n := range need {
		if !have[n] {
			miss = append(miss, "no "+n)
		}
	}
	return miss
}

// initrdFiles returns the name of every regular file in an lsinitrd list, a module's compression suffix dropped
// (btrfs.ko.zst is btrfs.ko). Only ls -l lines of regular files count: a unit, a generator or a link of the same name,
// or a name in dracut's module list, is not the file (#215).
func initrdFiles(list string) map[string]bool {
	have := map[string]bool{}
	for _, l := range strings.Split(list, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 || !strings.HasPrefix(f[0], "-") {
			continue
		}
		n := path.Base(f[len(f)-1])
		if mod, ext, ok := strings.Cut(n, ".ko."); ok && ext != "" && strings.Trim(ext, "abcdefghijklmnopqrstuvwxyz") == "" {
			n = mod + ".ko"
		}
		have[n] = true
	}
	return have
}

func hasLinePrefix(s, p string) bool {
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

var reDrivers = regexp.MustCompile(`(?m)^\s*(?:add|force)_drivers\+?=\s*"([^"]*)"`)

// RecordedDrivers maps the add_drivers (the root disk's driver chain) and force_drivers (the watchdog driver) of a
// dracut.conf (90-agentbox.conf) to the module files of one kernel, given its modules.dep and modules.builtin.
// Built-in drivers have no file and are skipped. A driver the kernel has in neither keeps its recorded name, so the
// gate reports it missing, as the install's modinfo check does.
// shortcut: no modules.alias lookup, so a renamed driver fails the gate until 90-agentbox.conf names the new one.
func RecordedDrivers(dracutConf, modulesDep, modulesBuiltin string) []string {
	files := map[string]string{} // nvme_core -> nvme-core.ko (any compression suffix matches in the initrd list)
	for _, l := range strings.Split(modulesDep, "\n") {
		if f, _, ok := strings.Cut(l, ":"); ok {
			b := path.Base(f)
			b = b[:strings.Index(b+".ko", ".ko")]
			files[strings.ReplaceAll(b, "-", "_")] = b + ".ko"
		}
	}
	for _, f := range strings.Fields(modulesBuiltin) {
		files[strings.ReplaceAll(strings.TrimSuffix(path.Base(f), ".ko"), "-", "_")] = ""
	}
	var out []string
	for _, m := range reDrivers.FindAllStringSubmatch(dracutConf, -1) {
		for _, d := range strings.Fields(m[1]) {
			f, ok := files[strings.ReplaceAll(d, "-", "_")]
			if !ok {
				f = d + ".ko"
			}
			if f != "" {
				out = append(out, f)
			}
		}
	}
	return out
}
