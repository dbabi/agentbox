// Command release builds an agentbox release; run it as `make release` from the repo root (PLAN.md milestones row
// 1–2). It writes agentbox-<ver>.tgz (install.sh, the systemd units, the sysusers.d and tmpfiles.d files, the op
// registry's generated gen/ files, agentbox for linux/arm64 and linux/amd64) and agentbox-<ver>.tgz.minisig. The
// tarball is reproducible (sorted entries, fixed mtime, root:root), so anyone can rebuild a commit with the same Go
// version and compare the hash a seed pins with --release-sha256.
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

// The version names /var/lib/agentbox/releases/<ver> on the box (install.sh checks the same charset) and the tarball,
// so it also stays inside the charset that agentbox seed accepts in a release URL.
var reVersion = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._~-]{0,63}$`)

// maxTarball is firstboot's curl --max-filesize (internal/seed/user-data.tmpl): every firstboot attempt would fail on a
// bigger release, so none is built.
var maxTarball int64 = 64 << 20

func main() {
	version := flag.String("version", "", "release version, e.g. 2026.11.1")
	key := flag.String("key", "", "minisign secret key file")
	unsigned := flag.Bool("unsigned", false, "build without signing (CI); hack/sign-release.sh rebuilds, compares and signs")
	out := flag.String("out", "dist", "output directory")
	flag.Parse()
	tgz, sum, err := build(*version, *key, *out, !*unsigned)
	if err != nil {
		fmt.Fprintln(os.Stderr, "release:", err)
		os.Exit(1)
	}
	if *unsigned {
		fmt.Printf("wrote %s (unsigned)\nsha256 %x\n", tgz, sum)
		return
	}
	fmt.Printf("wrote %s and %s.minisig\nseed flags: --release-url https://<host>/<path>/%s --release-sha256 %x\n", tgz, tgz, filepath.Base(tgz), sum)
}

// build writes the release and, if sign is set, signs it; it runs in the repo root.
func build(version, key, out string, sign bool) (string, []byte, error) {
	if !reVersion.MatchString(version) {
		return "", nil, fmt.Errorf("VERSION=%q: need [0-9A-Za-z][0-9A-Za-z._~-]*, at most 64 chars (it names the release dir on the box)", version)
	}
	var minisign string
	if sign {
		if key == "" {
			return "", nil, errors.New("MINISIGN_KEY (the minisign secret key file) is required")
		}
		if _, err := os.Stat(key); err != nil {
			return "", nil, err
		}
		var err error
		if minisign, err = exec.LookPath("minisign"); err != nil {
			return "", nil, errors.New("minisign not installed (brew install minisign / apt install minisign)")
		}
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
		// The caller's Go settings must not reach the binaries. GOENV=off drops `go env -w` ones, which an empty GOFLAGS=
		// would not override; v1 and v8.0 run on pre-AVX2 PCs and ARMv8.0 boards. GOTOOLCHAIN stays the caller's: it picks
		// the Go version.
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+arch, "GOENV=off", "GOWORK=off", "GOFLAGS=",
			"GOEXPERIMENT=", "GOFIPS140=off", "GOAMD64=v1", "GOARM64=v8.0")
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
	sysusers, _ := filepath.Glob("sysusers.d/*")
	tmpfiles, _ := filepath.Glob("tmpfiles.d/*")
	gen, _ := filepath.Glob("gen/*") // the op registry's generated files; rootd checks them at start (internal/ops)
	if len(gen) == 0 {
		return "", nil, errors.New("no gen/* files: run go generate ./internal/ops")
	}
	units = append(append(append(units, sysusers...), tmpfiles...), gen...)
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
	var fi os.FileInfo
	if err == nil {
		fi, err = os.Stat(f.Name())
	}
	if err == nil && fi.Size() > maxTarball {
		err = fmt.Errorf("%s would be %d bytes, over the %d that firstboot's curl --max-filesize (internal/seed/user-data.tmpl) accepts", tgz, fi.Size(), maxTarball)
	}
	if err == nil {
		err = os.Rename(f.Name(), tgz)
	}
	if err != nil || !sign {
		return tgz, h.Sum(nil), err
	}
	// The trusted comment is signed, and a fixed one keeps the signature reproducible (Ed25519 is deterministic).
	cmd := exec.Command(minisign, "-S", "-s", key, "-m", tgz, "-t", "agentbox "+version)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr // a password-protected key prompts here
	if err := cmd.Run(); err != nil {
		return "", nil, fmt.Errorf("minisign: %w", err)
	}
	return tgz, h.Sum(nil), nil
}
