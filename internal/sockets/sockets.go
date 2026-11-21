// Package sockets is the §2.1 socket inventory as code (ARCHITECTURE.md §2.1, A-arch-runtime-network-07): every
// runtime dir, Unix socket and FIFO, declared once with its owner, group, mode and creator. It generates the release's
// tmpfiles.d/agentbox.conf, ntfy's tmpfiles and the systemd .socket units (go test ./internal/sockets -update), and
// Check compares a live box with it (agentbox sockets check).
package sockets

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// Creators that make an entry at boot or install, so Check requires it.
const (
	Tmpfiles     = "tmpfiles.d/agentbox.conf"           // the release's, installed as /usr/lib/tmpfiles.d/agentbox.conf
	NtfyTmpfiles = "/etc/tmpfiles.d/agentbox-ntfy.conf" // written by reconcile once the ntfy package (and _ntfy) is in
)

// Entry is one path. A path, owner or group with <name> parts is a template (per task, agent or app): Check matches
// live entries against it but never requires one.
type Entry struct {
	Path        string
	Type        fs.FileMode // fs.ModeDir, fs.ModeSocket or fs.ModeNamedPipe
	User, Group string
	Mode        uint32 // permission bits plus setgid
	By          string // Tmpfiles, NtfyTmpfiles, a .socket unit, or the process that makes it at runtime
	Peers       string // who may connect (§2.1 "Allowed peers")
	// .socket units only
	Service, FDName string
	RemoveOnStop    bool
}

// Unit is the entry's .socket unit, or "" if PID 1 doesn't bind it.
func (e Entry) Unit() string {
	if strings.HasSuffix(e.By, ".socket") {
		return e.By
	}
	return ""
}

func (e Entry) required() bool {
	return !templated(e.Path) && (e.By == Tmpfiles || e.By == NtfyTmpfiles || e.Unit() != "")
}

var svcUser = map[string]string{"gate": "agentbox", "proxy": "agentbox-proxy", "keys": "agentbox-keys", "git": "agentbox-git"}

// Inventory is §2.1. Entries whose service isn't built yet name their creator in By but have no unit, so nothing
// generates them and Check doesn't require them; they get a unit here when their service lands.
func Inventory() []Entry {
	d, s := fs.ModeDir, fs.ModeSocket
	inv := []Entry{
		// the table gives admin.sock's dir only "0750"; agentbox-admin members must traverse it
		{Path: "/run/agentbox", Type: d, User: "root", Group: "agentbox-admin", Mode: 0o750, By: Tmpfiles},
		{Path: "/run/agentbox/admin.sock", Type: s, User: "root", Group: "agentbox-admin", Mode: 0o660, By: "agentboxd's .socket unit (not built yet)", Peers: "humans in agentbox-admin"},
		{Path: "/run/agentbox-rootd", Type: d, User: "root", Group: "root", Mode: 0o711, By: Tmpfiles},
		{Path: "/run/agentbox-rootd/rootd.sock", Type: s, User: "agentbox", Group: "agentbox", Mode: 0o600, By: "agentboxd's rootd .socket unit (not built yet)", Peers: "uid agentbox"},
		{Path: "/run/agentbox-rootd/rootd-admin.sock", Type: s, User: "root", Group: "agentbox-admin", Mode: 0o660, By: "agentbox-rootd-admin.socket", Peers: "Admin ops for root and agentbox-admin members", Service: "agentbox-rootd.service", FDName: "admin"},
		// §9: only rootd can set +a and +i, so rootd serves audit.Files to auditd here
		{Path: "/run/agentbox-rootd/audit-seal.sock", Type: s, User: "root", Group: "agentbox-audit", Mode: 0o660, By: "agentbox-audit-seal.socket", Peers: "audit.create and audit.seal from agentbox-auditd only (§9)", Service: "agentbox-rootd.service", FDName: "audit-seal"},
		{Path: "/run/agentbox-rootd/svc-<svc>.sock", Type: s, User: "<svc>", Group: "root", Mode: 0o600, By: "the brokers' .socket units (not built yet)", Peers: "uid 0 only"},
		{Path: "/run/agentbox-rootd-approve", Type: d, User: "root", Group: "agentbox-approve", Mode: 0o750, By: Tmpfiles},
		{Path: "/run/agentbox-rootd-approve/approve.sock", Type: s, User: "root", Group: "agentbox-approve", Mode: 0o660, By: "approvald's .socket unit (not built yet)", Peers: "uid agentbox-approve only"},
		{Path: "/run/agentbox-audit", Type: d, User: "agentbox-audit", Group: "agentbox-audit", Mode: 0o711, By: Tmpfiles},
		{Path: "/var/lib/agentbox/audit", Type: d, User: "agentbox-audit", Group: "agentbox-audit", Mode: 0o750, By: Tmpfiles}, // §9 chain
		{Path: "/run/agentbox-witness", Type: d, User: "root", Group: "root", Mode: 0o711, By: Tmpfiles},
		{Path: "/run/agentbox-witness/t", Type: d, User: "root", Group: "root", Mode: 0o711, By: Tmpfiles},
		{Path: "/run/agentbox-witness/t/<task>", Type: d, User: "root", Group: "ag-<agent>", Mode: 0o750, By: "rootd (task.start)"},
		{Path: "/run/agentbox-witness/t/<task>/witness", Type: fs.ModeNamedPipe, User: "root", Group: "ag-<agent>", Mode: 0o620, By: "rootd (task.start)", Peers: "written by the task's agent, read by rootd (§5.6)"},
		{Path: "/run/agentbox-llm/llama.sock", Type: s, User: "agentbox-llm", Group: "agentbox-keys", Mode: 0o660, By: "agentbox-llm@task (not built yet)", Peers: "agentbox-keys"},
		{Path: "/run/agentbox-llm-decide/llama.sock", Type: s, User: "agentbox-llm-decide", Group: "agentbox", Mode: 0o660, By: "agentbox-llm@decide (not built yet)", Peers: "agentbox"},
		{Path: "/run/agentbox-apps/<m>/in", Type: d, User: "app-<m>", Group: "agentbox-ingress", Mode: 0o2750, By: "rootd (app start)"},
		{Path: "/run/agentbox-apps/<m>/in/in.sock", Type: s, User: "<shim>", Group: "agentbox-ingress", Mode: 0o660, By: "the app's pod shim", Peers: "agentbox-ingress"},
		{Path: "/run/agentbox-apps/<m>/egress", Type: d, User: "agentbox-proxy", Group: "app-<m>", Mode: 0o2750, By: "rootd (app start)"},
		{Path: "/run/agentbox-apps/<m>/egress/egress.sock", Type: s, User: "agentbox-proxy", Group: "app-<m>", Mode: 0o660, By: "agentbox-proxy", Peers: "app-<m>"},
		// ntfy only chmods its socket and never chowns it, so the setgid dir gives the socket its group
		{Path: "/run/ntfy", Type: d, User: "_ntfy", Group: "agentbox-notify", Mode: 0o2750, By: NtfyTmpfiles},
		{Path: "/run/ntfy/ntfy.sock", Type: s, User: "_ntfy", Group: "agentbox-notify", Mode: 0o660, By: "ntfy (listen-unix)", Peers: "agentbox, rootd, ntfy-tcp proxy"},
		{Path: "/var/lib/ntfy", Type: d, User: "_ntfy", Group: "_ntfy", Mode: 0o750, By: NtfyTmpfiles},
	}
	for _, p := range []struct{ name, group string }{{"rootd", "root"}, {"agentboxd", "agentbox"}, {"proxy", "agentbox-proxy"}, {"keys", "agentbox-keys"}, {"git", "agentbox-git"}} {
		inv = append(inv, Entry{Path: "/run/agentbox-audit/" + p.name + ".sock", Type: s, User: "agentbox-audit", Group: p.group, Mode: 0o660,
			By: "agentbox-auditd-" + p.name + ".socket", Peers: p.name + "'s producer socket for agentbox-auditd", Service: "agentbox-auditd.service", FDName: p.name, RemoveOnStop: true})
	}
	for _, v := range []string{"proxy", "keys", "git"} {
		inv = append(inv, Entry{Path: "/run/agentbox-rootd/resolve-" + v + ".sock", Type: s, User: "root", Group: "agentbox-" + v, Mode: 0o660,
			By: "agentbox-rootd-resolve-" + v + ".socket", Peers: "Resolution requests from agentbox-" + v + " only (§6.3)", Service: "agentbox-rootd.service", FDName: "resolve-" + v})
	}
	for _, v := range []string{"gate", "proxy", "keys", "git"} {
		r := "/run/agentbox-" + v
		inv = append(inv,
			Entry{Path: r, Type: d, User: "root", Group: "root", Mode: 0o711, By: Tmpfiles},
			Entry{Path: r + "/t", Type: d, User: "root", Group: "root", Mode: 0o711, By: Tmpfiles},
			Entry{Path: r + "/t/<task>", Type: d, User: svcUser[v], Group: "ag-<agent>", Mode: 0o2750, By: "rootd (task.start)"},
			Entry{Path: r + "/t/<task>/" + v + ".sock", Type: s, User: svcUser[v], Group: "ag-<agent>", Mode: 0o660, By: "agentbox-" + v + " (umask 0117)", Peers: "the task's agent uid"})
	}
	sort.Slice(inv, func(i, j int) bool { return inv[i].Path < inv[j].Path })
	return inv
}

// TmpfilesLines is the tmpfiles.d body for one creator: one d line per dir, in inventory order.
func TmpfilesLines(inv []Entry, by string) string {
	var b strings.Builder
	for _, e := range inv {
		if e.By == by && e.Type == fs.ModeDir {
			fmt.Fprintf(&b, "d %s %04o %s %s -\n", e.Path, e.Mode, e.User, e.Group)
		}
	}
	return b.String()
}

// Files is every file the inventory generates in the repo, by repo-relative path.
func Files(inv []Entry) map[string]string {
	out := map[string]string{Tmpfiles: `# agentbox runtime and state dirs (ARCHITECTURE.md §2.1, §9), installed as /usr/lib/tmpfiles.d/agentbox.conf. Never
# RuntimeDirectory=: systemd deletes those when the unit stops. 0711 allows traversal, not listing.
# Generated from internal/sockets: go test ./internal/sockets -update
` + TmpfilesLines(inv, Tmpfiles)}
	mode := map[string]uint32{}
	for _, e := range inv {
		mode[e.Path] = e.Mode
	}
	for _, e := range inv {
		if e.Unit() == "" {
			continue
		}
		// DirectoryMode= matters only if tmpfiles hasn't run; keep it the dir's inventory mode anyway
		var b strings.Builder
		fmt.Fprintf(&b, "# %s (ARCHITECTURE.md §2.1).\n# PID 1 binds it with this owner and mode; the service checks SO_PEERCRED on every connection.\n", e.Peers)
		b.WriteString("# Generated from internal/sockets: go test ./internal/sockets -update\n[Unit]\n")
		fmt.Fprintf(&b, "Description=agentbox socket %s\n\n[Socket]\nListenStream=%s\nSocketUser=%s\nSocketGroup=%s\nSocketMode=%04o\nDirectoryMode=%04o\n",
			e.Path, e.Path, e.User, e.Group, e.Mode, mode[path.Dir(e.Path)])
		fmt.Fprintf(&b, "FileDescriptorName=%s\nService=%s\n", e.FDName, e.Service)
		if e.RemoveOnStop {
			b.WriteString("RemoveOnStop=yes\n")
		}
		b.WriteString("\n[Install]\nWantedBy=sockets.target\n")
		out["systemd/"+e.Unit()] = b.String()
	}
	return out
}

var tmpl = regexp.MustCompile(`<[^>]+>`)

func templated(s string) bool { return strings.Contains(s, "<") }

// match: a <name> part matches one path element or any name.
func match(pattern, s string) bool {
	ok, _ := path.Match(tmpl.ReplaceAllString(pattern, "*"), s)
	return ok
}

// Check compares the tree under root ("/" on the box) with inv, one line per mismatch: a required entry missing, a
// wrong type, mode, owner or group, or anything inside an inventory dir under /run that the inventory doesn't name.
func Check(root string, inv []Entry) []string {
	root = strings.TrimRight(root, "/")
	var bad []string
	exact := map[string]bool{}
	for _, e := range inv {
		exact[e.Path] = true
	}
	var walk func(dir string)
	visit := func(e Entry, p string, fi fs.FileInfo) {
		bad = append(bad, compare(e, p, fi)...)
		if e.Type == fs.ModeDir && fi.IsDir() && strings.HasPrefix(p, "/run/") {
			walk(p)
		}
	}
	walk = func(dir string) {
		des, err := os.ReadDir(root + dir)
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s: %v", dir, err))
			return
		}
		for _, de := range des {
			p := dir + "/" + de.Name()
			if exact[p] {
				continue // checked as its own entry
			}
			i := slices.IndexFunc(inv, func(e Entry) bool { return templated(e.Path) && match(e.Path, p) })
			if i < 0 {
				bad = append(bad, p+": not in the inventory")
				continue
			}
			if fi, err := os.Lstat(root + p); err != nil {
				bad = append(bad, fmt.Sprintf("%s: %v", p, err))
			} else {
				visit(inv[i], p, fi)
			}
		}
	}
	for _, e := range inv {
		if templated(e.Path) {
			continue
		}
		fi, err := os.Lstat(root + e.Path)
		switch {
		case errors.Is(err, fs.ErrNotExist) && !e.required():
		case err != nil:
			bad = append(bad, fmt.Sprintf("%s: %v (made by %s)", e.Path, err, e.By))
		default:
			visit(e, e.Path, fi)
		}
	}
	return bad
}

func compare(e Entry, p string, fi fs.FileInfo) []string {
	if fi.Mode().Type() != e.Type {
		return []string{fmt.Sprintf("%s: type %v, want %v", p, fi.Mode().Type(), e.Type)}
	}
	st := fi.Sys().(*syscall.Stat_t)
	var bad []string
	if m := uint32(st.Mode) & 0o7777; m != e.Mode {
		bad = append(bad, fmt.Sprintf("%s: mode %04o, want %04o", p, m, e.Mode))
	}
	u, g := strconv.Itoa(int(st.Uid)), strconv.Itoa(int(st.Gid))
	if x, err := user.LookupId(u); err == nil {
		u = x.Username
	}
	if x, err := user.LookupGroupId(g); err == nil {
		g = x.Name
	}
	if !match(e.User, u) || !match(e.Group, g) {
		bad = append(bad, fmt.Sprintf("%s: owner %s:%s, want %s:%s", p, u, g, e.User, e.Group))
	}
	return bad
}
