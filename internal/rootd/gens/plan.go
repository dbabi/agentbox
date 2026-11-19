package gens

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Plan is an os.apply closure bound to its base (§3.3 step 1). Its SHA-256 is what the human approves.
type Plan struct {
	BaseGen  string   `json:"baseGen"`  // the generation the plan was computed on
	BaseDpkg string   `json:"baseDpkg"` // SHA-256 of that generation's /var/lib/dpkg/status
	Request  []string `json:"request"`  // the apt-get install arguments the plan was computed from
	Actions  []Action `json:"actions"`  // every Inst/Remv from apt-get -s
	Debs     []Deb    `json:"debs"`     // every .deb the actions install
	EndState []string `json:"endState"` // installed package:arch=version set after the transaction
}

// Action is one apt-get -s line.
type Action struct {
	Op      string `json:"op"` // Inst or Remv
	Package string `json:"package"`
	Old     string `json:"old,omitempty"`     // installed version
	Version string `json:"version,omitempty"` // Inst: version to install
	Arch    string `json:"arch,omitempty"`    // Inst: that version's architecture
	Origin  string `json:"origin,omitempty"`  // Inst: archive origins, informational (the signed floor is weeks 11-12)
}

// Deb is one approved package file in the plan's directory.
type Deb struct {
	File   string `json:"file"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// URI is one apt-get --print-uris line.
type URI struct {
	URL, File string
	Size      int64
	HashType  string // MD5Sum, SHA1, SHA256 or SHA512: the first hash the signed index lists
	Hash      string
}

var (
	rePkg  = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+(:[a-z0-9-]+)?$`)
	reVer  = regexp.MustCompile(`^[A-Za-z0-9.+~:-]+$`)
	reInst = regexp.MustCompile(`^Inst (\S+)(?: \[(\S+)\])? \((\S+) (.+) \[([a-z0-9-]+)\]\)`)
	reRemv = regexp.MustCompile(`^(Remv|Purg) (\S+)(?: \[(\S+)\])?`)
	reURI  = regexp.MustCompile(`^'([^']+)' ([A-Za-z0-9.+~_%-]+\.deb) ([0-9]+) (MD5Sum|SHA1|SHA256|SHA512):([0-9a-f]+)$`)
)

// ParseSim reads the Inst/Remv lines of `apt-get -s install`; Purg is refused (week 1 plans never purge).
func ParseSim(out []byte) ([]Action, error) {
	var acts []Action
	for _, l := range strings.Split(string(out), "\n") {
		var a Action
		if m := reInst.FindStringSubmatch(l); m != nil {
			a = Action{Op: "Inst", Package: m[1], Old: m[2], Version: m[3], Origin: m[4], Arch: m[5]}
		} else if m := reRemv.FindStringSubmatch(l); m != nil {
			if m[1] == "Purg" {
				return nil, fmt.Errorf("apt-get -s: %q: purge is not supported", l)
			}
			a = Action{Op: "Remv", Package: m[2], Old: m[3]}
		} else if strings.HasPrefix(l, "Inst ") || strings.HasPrefix(l, "Remv ") || strings.HasPrefix(l, "Purg ") {
			return nil, fmt.Errorf("apt-get -s: unparsed line %q", l)
		} else {
			continue
		}
		if !rePkg.MatchString(a.Package) || (a.Version != "" && !reVer.MatchString(a.Version)) || (a.Old != "" && !reVer.MatchString(a.Old)) {
			return nil, fmt.Errorf("apt-get -s: unexpected package or version in %q", l)
		}
		acts = append(acts, a)
	}
	slices.SortFunc(acts, func(a, b Action) int { return strings.Compare(a.Package+" "+a.Op, b.Package+" "+b.Op) })
	return acts, nil
}

// ParseURIs reads `apt-get --print-uris install` output.
func ParseURIs(out []byte) ([]URI, error) {
	var us []URI
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if !strings.HasPrefix(l, "'") {
			continue
		}
		m := reURI.FindStringSubmatch(l)
		if m == nil {
			return nil, fmt.Errorf("apt-get --print-uris: unparsed line %q", l)
		}
		size, err := strconv.ParseInt(m[3], 10, 64)
		if err != nil {
			return nil, err
		}
		us = append(us, URI{URL: m[1], File: m[2], Size: size, HashType: m[4], Hash: m[5]})
	}
	return us, nil
}

// DebFile is apt's archive file name for a version: pkg_version_arch.deb with ':' quoted as %3a.
func DebFile(a Action) string {
	name, _, _ := strings.Cut(a.Package, ":")
	return name + "_" + strings.ReplaceAll(a.Version, ":", "%3a") + "_" + a.Arch + ".deb"
}

// Installed parses a dpkg status file into package:arch → version for every installed package.
func Installed(status []byte) (map[string]string, error) {
	inst := map[string]string{}
	for _, st := range strings.Split(string(status), "\n\n") {
		f := map[string]string{}
		for _, l := range strings.Split(st, "\n") {
			if k, v, ok := strings.Cut(l, ": "); ok && !strings.HasPrefix(l, " ") {
				f[k] = v
			}
		}
		if s := strings.Fields(f["Status"]); len(s) == 3 && s[2] == "installed" {
			if f["Package"] == "" || f["Architecture"] == "" || f["Version"] == "" {
				return nil, fmt.Errorf("dpkg status: incomplete stanza for %q", f["Package"])
			}
			inst[f["Package"]+":"+f["Architecture"]] = f["Version"]
		}
	}
	return inst, nil
}

// EndState applies acts to the installed set and returns the sorted package:arch=version list. native is dpkg's
// architecture: apt names that slot unqualified, and dpkg keeps one instance in it, arch all or native.
func EndState(inst map[string]string, acts []Action, native string) ([]string, error) {
	end := maps.Clone(inst)
	for _, a := range acts {
		name, arch, _ := strings.Cut(a.Package, ":")
		switch a.Op {
		case "Inst":
			if arch == "" { // an all <-> native upgrade replaces the old instance; foreign Multi-Arch: same ones stay
				delete(end, name+":all")
				delete(end, name+":"+native)
			}
			end[name+":"+a.Arch] = a.Version
		case "Remv":
			var keys []string
			for k := range end {
				if (arch != "" && k == a.Package) || (arch == "" && strings.HasPrefix(k, name+":")) {
					keys = append(keys, k)
				}
			}
			if len(keys) != 1 {
				return nil, fmt.Errorf("remove %s: matches %d installed packages", a.Package, len(keys))
			}
			delete(end, keys[0])
		}
	}
	var s []string
	for k, v := range end {
		s = append(s, k+"="+v)
	}
	slices.Sort(s)
	return s, nil
}

// AptArgs is the exact install list the build runs: pkg=version for every Inst, pkg- for every Remv, and
// --reinstall when an Inst keeps its version (apt otherwise skips it as already the newest).
func (p *Plan) AptArgs() []string {
	var args []string
	for _, a := range p.Actions {
		if a.Op == "Inst" && a.Old == a.Version {
			args = []string{"--reinstall"}
		}
	}
	for _, a := range p.Actions {
		if a.Op == "Inst" {
			args = append(args, a.Package+"="+a.Version)
		} else {
			args = append(args, a.Package+"-")
		}
	}
	return args
}

// Marshal is the plan's canonical bytes: fixed field order, slices sorted when the plan was made.
func (p *Plan) Marshal() []byte {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		panic(err) // plain strings and ints only
	}
	return append(b, '\n')
}

// Hash is the hex SHA-256 of b.
func Hash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// LoadPlan parses plan.json and checks that its bytes hash to the approved value and are canonical.
func LoadPlan(b []byte, approved string) (*Plan, error) {
	if h := Hash(b); h != approved {
		return nil, fmt.Errorf("plan sha256 is %s, not the approved %s", h, approved)
	}
	var p Plan
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, err
	}
	if !bytes.Equal(p.Marshal(), b) {
		return nil, fmt.Errorf("plan.json is not in canonical form")
	}
	return &p, nil
}

// SameActions reports whether apt's simulation inside the build equals the approved closure (§3.3 Apply step 2):
// the same packages, actions, versions and architectures. Old versions and origins are informational.
func SameActions(got, want []Action) bool {
	if len(got) != len(want) {
		return false
	}
	for i, g := range got {
		w := want[i]
		if g.Op != w.Op || g.Package != w.Package || g.Version != w.Version || g.Arch != w.Arch {
			return false
		}
	}
	return true
}
