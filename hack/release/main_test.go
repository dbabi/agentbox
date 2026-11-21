package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"debug/buildinfo"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"agentbox/internal/ops"
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
	tgz, sum, err := build("1.2.3-test", key, out, true)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(tgz)
	if err != nil {
		t.Fatal(err)
	}
	// The caller's Go settings, in the environment and in the `go env -w` file, must not reach the binaries. A missing
	// GOWORK file fails any build that reads it.
	goenv := filepath.Join(dir, "goenv")
	if err := os.WriteFile(goenv, []byte("GOFLAGS=-tags=leak\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"GOENV": goenv, "GOFLAGS": "-tags=leak", "GOAMD64": "v3", "GOARM64": "v8.1",
		"GOFIPS140": "latest", "GOWORK": filepath.Join(dir, "go.work")} {
		t.Setenv(k, v)
	}
	if _, again, err := build("1.2.3-test", key, out, true); err != nil || !bytes.Equal(sum, again) {
		t.Fatalf("a second build, with the caller's Go settings changed, differs: %v", err)
	}
	// CI builds unsigned and the owner rebuilds and signs: both must give the same bytes, and no signature
	if _, plain, err := build("1.2.3-test", "", out, false); err != nil || !bytes.Equal(sum, plain) {
		t.Fatalf("unsigned build: %v, sum %x, want %x", err, plain, sum)
	}
	if _, err := os.Stat(tgz + ".minisig"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unsigned build left a signature: %v", err)
	}
	if _, _, err := build("1.2.3-test", key, out, true); err != nil { // the checks below verify the signed release
		t.Fatal(err)
	}
	if b, err := exec.Command(ms, "-V", "-m", tgz, "-p", pub).CombinedOutput(); err != nil || !bytes.Contains(b, []byte("Trusted comment: agentbox 1.2.3-test")) {
		t.Fatalf("minisign -V: %v\n%s", err, b)
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	machine := map[string]elf.Machine{"bin/linux-amd64/agentbox": elf.EM_X86_64, "bin/linux-arm64/agentbox": elf.EM_AARCH64}
	level := map[string]string{"bin/linux-amd64/agentbox": "GOAMD64=v1", "bin/linux-arm64/agentbox": "GOARM64=v8.0"}
	mode := map[string]int64{"bin/linux-amd64/agentbox": 0o755, "bin/linux-arm64/agentbox": 0o755, "install.sh": 0o755}
	want := "bin/linux-amd64/agentbox bin/linux-arm64/agentbox install.sh"
	units, _ := filepath.Glob("systemd/*") // sorted, and every unit in the repo ships
	sysusers, _ := filepath.Glob("sysusers.d/*")
	tmpfiles, _ := filepath.Glob("tmpfiles.d/*")
	units = append(append(units, sysusers...), tmpfiles...)
	for _, g := range ops.Shipped { // exactly these, whatever else sits in gen/
		units = append(units, "gen/"+g)
	}
	all := strings.Fields(want)
	for _, u := range units {
		mode[u] = 0o644
		all = append(all, u)
	}
	sort.Strings(all) // the tarball's order
	want = strings.Join(all, " ")
	if !strings.Contains(want, "systemd/agentbox-reconcile.service") || !strings.Contains(want, "sysusers.d/agentbox.conf") ||
		!strings.Contains(want, "tmpfiles.d/agentbox.conf") || !strings.Contains(want, "gen/cedar.schema") {
		t.Fatal("systemd/agentbox-reconcile.service, sysusers.d/agentbox.conf or tmpfiles.d/agentbox.conf is missing from the repo")
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
			// the baseline levels: the old-PC target has no AVX2
			if bi, err := buildinfo.Read(bytes.NewReader(b)); err != nil || !strings.Contains(bi.String(), "\nbuild\t"+level[h.Name]+"\n") {
				t.Errorf("%s: want %s in its build info (%v)", h.Name, level[h.Name], err)
			}
		}
	}
	if got := strings.Join(names, " "); got != want {
		t.Errorf("entries: %s, want %s", got, want)
	}
	for _, v := range []string{"", "../x", ".hidden", "1 2", "a/b", "1.0+git", strings.Repeat("1", 65)} {
		if _, _, err := build(v, key, out, true); err == nil {
			t.Errorf("version %q accepted", v)
		}
	}
	// firstboot's curl refuses a release over its cap, so make release must not build one
	if b, err := os.ReadFile("internal/seed/user-data.tmpl"); err != nil || !bytes.Contains(b, fmt.Appendf(nil, " --max-filesize %dM", maxTarball>>20)) {
		t.Errorf("internal/seed/user-data.tmpl: want firstboot's curl capped at the release limit, %d MiB (%v)", maxTarball>>20, err)
	}
	defer func(n int64) { maxTarball = n }(maxTarball)
	maxTarball = int64(len(data)) - 1
	if _, _, err := build("1.2.3-test", key, out, true); err == nil || !strings.Contains(err.Error(), "--max-filesize") {
		t.Errorf("a release 1 byte over the cap was built: %v", err)
	}
}
