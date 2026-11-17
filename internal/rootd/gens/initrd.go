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
	Drivers   []string // add_drivers recorded at install that are modules in this kernel (file base names)
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

var reAddDrivers = regexp.MustCompile(`(?m)^\s*add_drivers\+?=\s*"([^"]*)"`)

// RecordedDrivers maps the add_drivers of a dracut.conf (90-agentbox.conf) to the module files of one kernel,
// given its modules.dep. Built-in drivers have no file and are skipped ("if it is a module in K").
func RecordedDrivers(dracutConf, modulesDep string) []string {
	files := map[string]string{} // nvme_core -> nvme-core.ko (any compression suffix matches in the initrd list)
	for _, l := range strings.Split(modulesDep, "\n") {
		if f, _, ok := strings.Cut(l, ":"); ok {
			b := path.Base(f)
			b = b[:strings.Index(b+".ko", ".ko")]
			files[strings.ReplaceAll(b, "-", "_")] = b + ".ko"
		}
	}
	var out []string
	for _, m := range reAddDrivers.FindAllStringSubmatch(dracutConf, -1) {
		for _, d := range strings.Fields(m[1]) {
			if f, ok := files[strings.ReplaceAll(d, "-", "_")]; ok {
				out = append(out, f)
			}
		}
	}
	return out
}
