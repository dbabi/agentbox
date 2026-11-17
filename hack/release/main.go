// Command release builds an agentbox release; run it as `make release` from the repo root (PLAN.md milestones row
// 1–2). It writes agentbox-<ver>.tgz (install.sh, the systemd units, agentbox for linux/arm64 and linux/amd64) and
// agentbox-<ver>.tgz.minisig. The tarball is reproducible (sorted entries, fixed mtime, root:root), so anyone can
// rebuild a commit with the same Go version and compare the hash a seed pins with --release-sha256.
package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"time"
)

// The version names /var/lib/agentbox/releases/<ver> on the box; install.sh checks the same charset.
var reVersion = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+~_-]{0,63}$`)

func main() {
	version := flag.String("version", "", "release version, e.g. 2026.11.1")
	key := flag.String("key", "", "minisign secret key file")
	out := flag.String("out", "dist", "output directory")
	flag.Parse()
	tgz, sum, err := build(*version, *key, *out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "release:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s and %s.minisig\nseed flags: --release-url https://<host>/<path>/%s --release-sha256 %x\n", tgz, tgz, filepath.Base(tgz), sum)
}

// build writes and signs the release; it runs in the repo root.
func build(version, key, out string) (string, []byte, error) {
	if !reVersion.MatchString(version) {
		return "", nil, fmt.Errorf("VERSION=%q: need [0-9A-Za-z][0-9A-Za-z.+~_-]*, at most 64 chars (it names the release dir on the box)", version)
	}
	if key == "" {
		return "", nil, errors.New("MINISIGN_KEY (the minisign secret key file) is required")
	}
	if _, err := os.Stat(key); err != nil {
		return "", nil, err
	}
	minisign, err := exec.LookPath("minisign")
	if err != nil {
		return "", nil, errors.New("minisign not installed (brew install minisign / apt install minisign)")
	}
	tmp, err := os.MkdirTemp("", "agentbox-release-")
	if err != nil {
		return "", nil, err
	}
	defer os.RemoveAll(tmp)
	type file struct {
		name, src string
		mode      int64
	}
	files := []file{{"install.sh", "install/install.sh", 0o755}}
	for _, arch := range []string{"arm64", "amd64"} {
		bin := filepath.Join(tmp, arch)
		cmd := exec.Command("go", "build", "-trimpath", "-ldflags", "-s -w -X main.version="+version, "-o", bin, "./cmd/agentbox")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+arch)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Run(); err != nil {
			return "", nil, fmt.Errorf("go build linux/%s: %w", arch, err)
		}
		files = append(files, file{"bin/linux-" + arch + "/agentbox", bin, 0o755})
	}
	units, _ := filepath.Glob("systemd/*")
	if len(units) == 0 {
		return "", nil, errors.New("no systemd/* units: run from the repo root")
	}
	for _, u := range units {
		files = append(files, file{u, u, 0o644})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })

	if err := os.MkdirAll(out, 0o755); err != nil {
		return "", nil, err
	}
	tgz := filepath.Join(out, "agentbox-"+version+".tgz")
	if err := os.Remove(tgz + ".minisig"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", nil, err // an old signature must never sit next to a new tarball
	}
	f, err := os.CreateTemp(out, ".agentbox-release-*")
	if err != nil {
		return "", nil, err
	}
	defer os.Remove(f.Name()) // no-op once renamed
	h := sha256.New()
	zw, _ := gzip.NewWriterLevel(io.MultiWriter(f, h), gzip.BestCompression) // zero header: no name, no mtime
	tw := tar.NewWriter(zw)
	mtime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) // fixed, so the same commit gives the same tarball
	for _, fl := range files {
		b, err := os.ReadFile(fl.src)
		if err != nil {
			f.Close()
			return "", nil, err
		}
		hdr := &tar.Header{Typeflag: tar.TypeReg, Name: fl.name, Mode: fl.mode, Size: int64(len(b)), ModTime: mtime, Uname: "root", Gname: "root"}
		if err := tw.WriteHeader(hdr); err != nil {
			f.Close()
			return "", nil, err
		}
		if _, err := tw.Write(b); err != nil {
			f.Close()
			return "", nil, err
		}
	}
	err = errors.Join(tw.Close(), zw.Close(), f.Chmod(0o644), f.Close()) // in this order: tar flushes into gzip, gzip into f
	if err == nil {
		err = os.Rename(f.Name(), tgz)
	}
	if err != nil {
		return "", nil, err
	}
	// The trusted comment is signed, and a fixed one keeps the signature reproducible (Ed25519 is deterministic).
	cmd := exec.Command(minisign, "-S", "-s", key, "-m", tgz, "-t", "agentbox "+version)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr // a password-protected key prompts here
	if err := cmd.Run(); err != nil {
		return "", nil, fmt.Errorf("minisign: %w", err)
	}
	return tgz, h.Sum(nil), nil
}
