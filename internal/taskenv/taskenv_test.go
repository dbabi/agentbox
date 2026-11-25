package taskenv

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestEnv(t *testing.T) {
	on := Env(true, "corp.example/*")
	for _, want := range []string{"GOPROXY=https://proxy.golang.org,direct", "GOSUMDB=sum.golang.org",
		"GOTOOLCHAIN=local", "GOPRIVATE=corp.example/*", "HTTPS_PROXY=http://127.0.0.1:8080", "https_proxy=http://127.0.0.1:8080",
		"NO_PROXY=127.0.0.1,localhost,::1", "no_proxy=127.0.0.1,localhost,::1", "npm_config_audit=false",
		"npm_config_fund=false", "npm_config_update_notifier=false", "NO_UPDATE_NOTIFIER=1", "PIP_DISABLE_PIP_VERSION_CHECK=1"} {
		if !slices.Contains(on, want) {
			t.Errorf("with proxy.golang.org: no %s in %q", want, on)
		}
	}
	// #223: nothing serves the Go module filter yet, and go stops at a GOPROXY entry it can't reach
	if s := strings.Join(on, " "); strings.Contains(s, ":8083") {
		t.Errorf("an env entry names the Go module filter: %s", s)
	}
	off := Env(false, "")
	if !slices.Contains(off, "GOPROXY=off") || !slices.Contains(off, "GOTOOLCHAIN=local") {
		t.Errorf("without proxy.golang.org: %q", off)
	}
	for _, e := range append(on, off...) {
		k, _, _ := strings.Cut(e, "=")
		if slices.Contains(Unset, k) || (k == "GOSUMDB" && slices.Contains(off, e)) || (k == "GOPRIVATE" && slices.Contains(off, e)) {
			t.Errorf("sets %s", e)
		}
	}
	if a := PodmanArgs(false, ""); a[0] != "-e" || len(a) != 2*len(off) {
		t.Errorf("PodmanArgs: %q", a)
	}
}

func TestGoPrivate(t *testing.T) {
	for _, ok := range []string{"", "corp.example/*", "corp.example/*,git.corp.example/team/?x,[a-c].example"} {
		if err := ValidGoPrivate(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{",", "a,,b", "a b", "corp.example/[", "x\n", "x;rm", "é.example", strings.Repeat("a", MaxPrivate+1)} {
		if ValidGoPrivate(bad) == nil {
			t.Errorf("%q passes", bad)
		}
	}
	dir := t.TempDir()
	if c, err := WriteGoPrivate(dir, "ga", "corp.example/*"); !c || err != nil {
		t.Fatal(c, err)
	}
	if c, err := WriteGoPrivate(dir, "ga", "corp.example/*"); c || err != nil {
		t.Fatal("rewrite of the same patterns:", c, err)
	}
	if _, err := WriteGoPrivate(dir, "../x", "a"); err == nil {
		t.Fatal("bad agent name accepted")
	}
	os.WriteFile(filepath.Join(dir, "gb.list"), []byte("proxy.golang.org:443\n"), 0o644)
	a, err := ForAgent(dir, "ga")
	if err != nil || !slices.Contains(a, "GOPROXY=off") || !slices.Contains(a, "GOPRIVATE=corp.example/*") {
		t.Fatalf("ga: %q %v", a, err)
	}
	if a, _ := ForAgent(dir, "gb"); !slices.Contains(a, "GOSUMDB=sum.golang.org") || slices.ContainsFunc(a, func(s string) bool { return strings.HasPrefix(s, "GOPRIVATE=") }) {
		t.Fatalf("gb: %q", a)
	}
	os.WriteFile(filepath.Join(dir, "ga.goprivate"), []byte("a b\n"), 0o644) // hand-edited: never reaches the env
	if _, err := ForAgent(dir, "ga"); err == nil {
		t.Fatal("an invalid .goprivate file reached the env")
	}
	if c, err := WriteGoPrivate(dir, "ga", ""); !c || err != nil {
		t.Fatal("clear:", c, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ga.goprivate")); !os.IsNotExist(err) {
		t.Fatal("clear left the file")
	}
}

// The image's resolv.conf is the one this package names.
func TestImageResolvConf(t *testing.T) {
	b, err := os.ReadFile("../../image/task/resolv.conf")
	if err != nil || string(b) != ResolvConf {
		t.Fatalf("image/task/resolv.conf: %q %v", b, err)
	}
}
