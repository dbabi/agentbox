package sockets

import (
	"flag"
	"io/fs"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
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
		{Path: "/run/a/t-<task>/x.sock", Type: fs.ModeSocket, User: me, Group: grp, Mode: 0o660, By: "svc"},
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
	os.Remove(root + "/run/a/t-1")
	l.Close()
	os.Remove(root + "/run/a/s.sock")
	want("a missing unit socket", "/run/a/s.sock: lstat")
	if bad := strings.Join(Check(root, inv), "\n"); strings.Contains(bad, "later.sock") {
		t.Errorf("a socket of an unbuilt service is required: %q", bad)
	}
}
