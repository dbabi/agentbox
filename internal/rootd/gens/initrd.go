package gens

import (
	"path"
	"regexp"
	"strings"
)

// Mode is what the initrd gate requires of every initrd in a new generation (§3.3 step 4).
type Mode struct {
	Encrypted bool     // root on LUKS (crypttab has croot)
	Tang      bool     // the clevis binding has a tang pin
	Drivers   []string // add_drivers and force_drivers recorded at install, unless built into this kernel (file base names)
}

// InitrdProblems returns what one initrd lacks, given `lsinitrd` (its file list) and `lsinitrd -f etc/crypttab`.
func InitrdProblems(list, crypttab string, m Mode) []string {
	var miss []string
	need := []string{"/btrfs.ko"}
	if m.Encrypted {
		if !hasLinePrefix(crypttab, "croot ") {
			miss = append(miss, "etc/crypttab has no croot line")
		}
		need = append(need, "clevis-luks-askpass", "/systemd-cryptsetup")
	}
	if m.Tang {
		need = append(need, "clevis-decrypt-tang")
	}
	for _, d := range m.Drivers {
		need = append(need, "/"+d)
	}
	for _, n := range need {
		if !strings.Contains(list, n) {
			miss = append(miss, "no "+strings.TrimPrefix(n, "/"))
		}
	}
	return miss
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
