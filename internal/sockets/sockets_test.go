package sockets

import (
	"flag"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the generated files in the repo")

// The release ships the repo's tmpfiles.d and systemd/*.socket files; they must be exactly what the inventory makes.
func TestGeneratedFiles(t *testing.T) {
	files := Files(Inventory())
	for rel, want := range files {
		p := filepath.Join("..", "..", rel)
		if *update {
			if err := os.WriteFile(p, []byte(want), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if got, err := os.ReadFile(p); err != nil || string(got) != want {
			t.Errorf("%s differs from the inventory (go test ./internal/sockets -update): %v", rel, err)
		}
	}
	units, _ := filepath.Glob("../../systemd/*.socket")
	for _, u := range units {
		if _, ok := files["systemd/"+filepath.Base(u)]; !ok {
			t.Errorf("%s is not in the inventory", u)
		}
	}
	if len(units) == 0 {
		t.Error("no systemd/*.socket in the repo")
	}
}

// Every concrete path is unique, and every user and group exists on the box: from sysusers.d, the ntfy package or root.
func TestInventoryNames(t *testing.T) {
	b, err := os.ReadFile("../../sysusers.d/agentbox.conf")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{"root": true, "_ntfy": true}
	for _, m := range regexp.MustCompile(`(?m)^[ug]\s+(\S+)`).FindAllStringSubmatch(string(b), -1) {
		names[m[1]] = true
	}
	seen := map[string]bool{}
	for _, e := range Inventory() {
		if seen[e.Path] {
			t.Errorf("%s twice", e.Path)
		}
		seen[e.Path] = true
		for _, n := range []string{e.User, e.Group} {
			if !templated(n) && !names[n] {
				t.Errorf("%s: %s is in no sysusers.d line", e.Path, n)
			}
		}
		if e.Unit() != "" && (e.Type != fs.ModeSocket || e.Service == "" || e.FDName == "") {
			t.Errorf("%s: a .socket unit entry needs a socket type, Service and FDName", e.Path)
		}
	}
}

// The inventory covers §2.1 and the §2 ntfy tmpfiles: every tmpfiles line in the design is generated, and every socket
// the table names has an entry (a <name> in the design matches any one name).
func TestInventoryMatchesDesign(t *testing.T) {
	b, err := os.ReadFile("../../docs/design/ARCHITECTURE.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	doc = doc[strings.Index(doc, "\n## 2. Services and sockets"):strings.Index(doc, "\n## 3. ")]
	inv := Inventory()
	gen := TmpfilesLines(inv, Tmpfiles) + TmpfilesLines(inv, NtfyTmpfiles)
	lines := regexp.MustCompile("`(d /\\S+ \\d{4} \\S+ \\S+ -)`").FindAllStringSubmatch(doc, -1)
	if len(lines) < 8 {
		t.Fatalf("found only %d tmpfiles lines in the design", len(lines))
	}
	for _, m := range lines {
		for _, v := range []string{"gate", "proxy", "keys", "git"} {
			if l := strings.ReplaceAll(m[1], "<svc>", v); !strings.Contains(gen, l+"\n") {
				t.Errorf("design tmpfiles line %q is not generated", l)
			}
		}
	}
	socks := regexp.MustCompile("`(/run/[^`\\s]+(?:\\.sock|/witness))`").FindAllStringSubmatch(doc, -1)
	if len(socks) < 10 {
		t.Fatalf("found only %d sockets in the design", len(socks))
	}
	for _, m := range socks {
		re := regexp.MustCompile("^" + tmpl.ReplaceAllString(regexp.QuoteMeta(m[1]), `[^/]+`) + "$")
		if !slices.ContainsFunc(inv, func(e Entry) bool { return re.MatchString(e.Path) }) {
			t.Errorf("design socket %s has no inventory entry", m[1])
		}
	}
	// every socket's dir is in the inventory, so Check walks it, and a fixed dir is made at boot
	byPath := map[string]Entry{}
	for _, e := range inv {
		byPath[e.Path] = e
	}
	for _, e := range inv {
		if e.Type == fs.ModeDir {
			continue
		}
		d, ok := byPath[path.Dir(e.Path)]
		switch {
		case !ok || d.Type != fs.ModeDir:
			t.Errorf("%s: its dir is not an inventory dir", e.Path)
		case !templated(d.Path) && d.By != Tmpfiles && d.By != NtfyTmpfiles:
			t.Errorf("%s: its dir %s is made by %s, not tmpfiles", e.Path, d.Path, d.By)
		}
	}
}

// uidOf is the service uid a <svc> or <producer> in a §2.1 owner or group cell stands for.
var uidOf = map[string]string{"rootd": "root", "agentboxd": "agentbox", "gate": "agentbox", "proxy": "agentbox-proxy", "keys": "agentbox-keys", "git": "agentbox-git"}

// The inventory has each §2.1 table row's owner, group and mode, for the socket and, where the row gives one, its dir.
// A <svc> or <producer> is the uid of the service the path names; any other <name> stays a template.
func TestInventoryOwnersMatchDesign(t *testing.T) {
	b, err := os.ReadFile("../../docs/design/ARCHITECTURE.md")
	if err != nil {
		t.Fatal(err)
	}
	row := regexp.MustCompile("(?m)^\\| `(/run/[^`]+)`[^|]*\\| ([^|]+) \\|")
	cell := regexp.MustCompile(`(?:(dir|FIFO|socket) )?(?:([\w<>-]+)(?::([\w<>-]+))? )?(\d{4})`)
	byPath := map[string]Entry{}
	for _, e := range Inventory() {
		byPath[e.Path] = e
	}
	rows := row.FindAllStringSubmatch(string(b), -1)
	if len(rows) < 14 {
		t.Fatalf("found only %d socket rows in the §2.1 table", len(rows))
	}
	n := 0
	for _, r := range rows {
		c := strings.NewReplacer("`", "", "**", "").Replace(r[2])
		for _, e := range Inventory() {
			vals, ok := bind(r[1], e.Path, nil)
			if !ok || templated(e.Path) && !strings.Contains(r[1], "<") {
				continue
			}
			n++
			for _, m := range cell.FindAllStringSubmatch(c, -1) {
				want := Entry{Path: e.Path, User: m[2], Group: m[3]}
				fmt.Sscanf(m[4], "%o", &want.Mode)
				if m[1] == "dir" {
					want.Path = path.Dir(e.Path)
				}
				got, ok := byPath[want.Path]
				if !ok {
					t.Errorf("%s (row %s): no inventory entry", want.Path, r[1])
					continue
				}
				for _, f := range []*string{&want.User, &want.Group} {
					*f = tmpl.ReplaceAllStringFunc(*f, func(n string) string {
						if v, ok := uidOf[vals[n]]; ok && (n == "<svc>" || n == "<producer>") {
							return v
						}
						return n
					})
				}
				if got.Mode != want.Mode || want.User != "" && got.User != want.User || want.Group != "" && got.Group != want.Group {
					t.Errorf("%s: inventory %s:%s %04o, §2.1 says %s:%s %04o", want.Path, got.User, got.Group, got.Mode, want.User, want.Group, want.Mode)
				}
			}
		}
	}
	if n < 20 {
		t.Errorf("only %d inventory entries matched a §2.1 row", n)
	}
}

func TestCheck(t *testing.T) {
	root, err := os.MkdirTemp("", "sk") // short: macOS caps a socket path at 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	u, _ := user.Current()
	g, _ := user.LookupGroupId(u.Gid)
	me, grp := u.Username, g.Name
	inv := []Entry{
		{Path: "/run/a", Type: fs.ModeDir, User: me, Group: grp, Mode: 0o711, By: Tmpfiles},
		{Path: "/run/a/s.sock", Type: fs.ModeSocket, User: me, Group: grp, Mode: 0o660, By: "a.socket"},
		{Path: "/run/a/later.sock", Type: fs.ModeSocket, User: me, Group: grp, Mode: 0o600, By: "not built yet"},
		{Path: "/run/a/t-<task>", Type: fs.ModeDir, User: me, Group: "<any>", Mode: 0o750, By: "rootd"}, // macOS drops setgid for non-root; the VM gate covers 2750
		{Path: "/run/a/t-<task>/x.sock", Type: fs.ModeSocket, User: me, Group: "<any>", Mode: 0o660, By: "svc"},
		{Path: "/run/a/svc-x.sock", Type: fs.ModeSocket, User: "nobody", Group: grp, Mode: 0o600, By: "not built yet"},
	}
	os.MkdirAll(root+"/run/a", 0o711)
	os.Chmod(root+"/run/a", 0o711)
	l, err := net.Listen("unix", root+"/run/a/s.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	os.Chmod(root+"/run/a/s.sock", 0o660)
	if bad := Check(root+"/", inv); len(bad) != 0 {
		t.Fatalf("a matching tree: %q", bad)
	}
	want := func(name string, sub ...string) {
		t.Helper()
		bad := strings.Join(Check(root, inv), "\n")
		for _, s := range sub {
			if !strings.Contains(bad, s) {
				t.Errorf("%s: want %q in %q", name, s, bad)
			}
		}
	}
	os.Chmod(root+"/run/a/s.sock", 0o666)
	want("wrong socket mode", "/run/a/s.sock: mode 0666, want 0660")
	os.Chmod(root+"/run/a/s.sock", 0o660)
	inv[1].User = "nobody-such"
	want("wrong socket owner", "/run/a/s.sock: owner "+me+":"+grp+", want nobody-such:"+grp)
	inv[1].User = me
	os.WriteFile(root+"/run/a/stray", nil, 0o600)
	want("stray file", "/run/a/stray: not in the inventory")
	os.Remove(root + "/run/a/stray")
	os.Mkdir(root+"/run/a/t-1", 0o750)
	os.Chmod(root+"/run/a/t-1", 0o750)
	os.WriteFile(root+"/run/a/t-1/x.sock", nil, 0o660)
	want("a regular file where a templated socket goes", "/run/a/t-1/x.sock: type ----------, want S---------")
	os.Remove(root + "/run/a/t-1/x.sock")
	if bad := Check(root, inv); len(bad) != 0 {
		t.Errorf("a templated dir with the right mode: %q", bad)
	}
	os.Chmod(root+"/run/a/t-1", 0o700)
	want("a templated dir with the wrong mode", "/run/a/t-1: mode 0700, want 0750")
	os.Chmod(root+"/run/a/t-1", 0o750)
	x, err := net.Listen("unix", root+"/run/a/t-1/x.sock")
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(root+"/run/a/t-1/x.sock", 0o660)
	if bad := Check(root, inv); len(bad) != 0 {
		t.Errorf("a per-task socket in its dir's group: %q", bad)
	}
	fi, _ := os.Stat(root + "/run/a/t-1")
	dg := strconv.Itoa(int(fi.Sys().(*syscall.Stat_t).Gid))
	gids, _ := u.GroupIds()
	if i := slices.IndexFunc(gids, func(g string) bool { return g != dg }); i < 0 {
		t.Log("one group only: skipping the per-task group binding case")
	} else if other, err := user.LookupGroupId(gids[i]); err == nil {
		gid, _ := strconv.Atoi(gids[i])
		os.Lchown(root+"/run/a/t-1/x.sock", -1, gid)
		dn, _ := user.LookupGroupId(dg)
		want("a per-task socket in another group than its dir", "/run/a/t-1/x.sock: owner "+me+":"+other.Name+", want "+me+":"+dn.Name)
	}
	// a task that stops mid-check is not a mismatch: its dir goes after ReadDir lists it, or after it is checked
	for _, after := range []bool{false, true} {
		lstat = func(p string) (fs.FileInfo, error) {
			if !strings.HasSuffix(p, "/t-1") {
				return os.Lstat(p)
			}
			if after {
				fi, err := os.Lstat(p)
				os.RemoveAll(p)
				return fi, err
			}
			os.RemoveAll(p)
			return os.Lstat(p)
		}
		os.MkdirAll(root+"/run/a/t-1", 0o750)
		os.Chmod(root+"/run/a/t-1", 0o750)
		if bad := Check(root, inv); len(bad) != 0 {
			t.Errorf("a per-task dir removed mid-check (after its Lstat: %v): %q", after, bad)
		}
	}
	lstat = os.Lstat
	x.Close()
	l2, err := net.Listen("unix", root+"/run/a/svc-x.sock")
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(root+"/run/a/svc-x.sock", 0o600)
	want("a service socket owned by the wrong user", "/run/a/svc-x.sock: owner "+me+":"+grp+", want nobody:"+grp)
	l2.Close()
	os.Remove(root + "/run/a/svc-x.sock")
	os.RemoveAll(root + "/run/a/t-1")
	l.Close()
	os.Remove(root + "/run/a/s.sock")
	want("a missing unit socket", "/run/a/s.sock: lstat")
	if bad := strings.Join(Check(root, inv), "\n"); strings.Contains(bad, "later.sock") {
		t.Errorf("a socket of an unbuilt service is required: %q", bad)
	}
}
