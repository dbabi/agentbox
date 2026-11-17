package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"debug/elf"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestBuild builds one release twice: the same bytes both times, root-owned entries with fixed modes, one ELF per
// architecture carrying the version, and a signature that minisign verifies with the version as trusted comment.
func TestBuild(t *testing.T) {
	ms, err := exec.LookPath("minisign")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("CI needs minisign")
		}
		t.Skip("minisign not installed")
	}
	t.Chdir("../..")
	dir := t.TempDir()
	key, pub, out := filepath.Join(dir, "k.key"), filepath.Join(dir, "k.pub"), filepath.Join(dir, "dist")
	if b, err := exec.Command(ms, "-G", "-W", "-s", key, "-p", pub).CombinedOutput(); err != nil {
		t.Fatalf("minisign -G: %v\n%s", err, b)
	}
	tgz, sum, err := build("1.2.3-test", key, out)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(tgz)
	if err != nil {
		t.Fatal(err)
	}
	if _, again, err := build("1.2.3-test", key, out); err != nil || !bytes.Equal(sum, again) {
		t.Fatalf("a second build of the same tree differs: %v", err)
	}
	if b, err := exec.Command(ms, "-V", "-m", tgz, "-p", pub).CombinedOutput(); err != nil || !bytes.Contains(b, []byte("Trusted comment: agentbox 1.2.3-test")) {
		t.Fatalf("minisign -V: %v\n%s", err, b)
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	machine := map[string]elf.Machine{"bin/linux-amd64/agentbox": elf.EM_X86_64, "bin/linux-arm64/agentbox": elf.EM_AARCH64}
	mode := map[string]int64{"bin/linux-amd64/agentbox": 0o755, "bin/linux-arm64/agentbox": 0o755, "install.sh": 0o755}
	want := "bin/linux-amd64/agentbox bin/linux-arm64/agentbox install.sh"
	units, _ := filepath.Glob("systemd/*") // sorted, and every unit in the repo ships
	for _, u := range units {
		mode[u] = 0o644
		want += " " + u
	}
	if !strings.Contains(want, "systemd/agentbox-reconcile.service") {
		t.Fatal("systemd/agentbox-reconcile.service is missing from the repo")
	}
	var names []string
	for tr := tar.NewReader(zr); ; {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
		if h.Typeflag != tar.TypeReg || h.Mode != mode[h.Name] || h.Uid != 0 || h.Gid != 0 || h.Uname != "root" {
			t.Errorf("%s: type %c mode %o owner %d:%d %s", h.Name, h.Typeflag, h.Mode, h.Uid, h.Gid, h.Uname)
		}
		if m, ok := machine[h.Name]; ok {
			b, _ := io.ReadAll(tr)
			if f, err := elf.NewFile(bytes.NewReader(b)); err != nil || f.Machine != m || !bytes.Contains(b, []byte("1.2.3-test")) {
				t.Errorf("%s: want a %v ELF that carries the version (%v)", h.Name, m, err)
			}
		}
	}
	if got := strings.Join(names, " "); got != want {
		t.Errorf("entries: %s, want %s", got, want)
	}
	for _, v := range []string{"", "../x", ".hidden", "1 2", "a/b", "1.0+git", strings.Repeat("1", 65)} {
		if _, _, err := build(v, key, out); err == nil {
			t.Errorf("version %q accepted", v)
		}
	}
}
