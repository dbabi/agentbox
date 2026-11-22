package hack

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Fake gh, git and go for sign-release.sh. gh serves the draft from $REL and logs every call; git clones nothing;
// go logs its arguments and environment and "builds" by copying CI's tarball.
var signFakes = map[string]string{
	"gh": `echo "gh $*" >> "$LOG"
case "$1 $2" in
"release download") while [ $# -gt 0 ]; do [ "$1" = -D ] && d=$2; shift; done; mkdir -p "$d" && cp "$REL"/* "$d"/ ;;
"run list") case "$*" in *"--workflow ci "*) echo "$CI_RUNS" ;; *) echo 1 ;; esac ;;
"release upload") cp "$6" "$OUT"/ ;; # release upload <tag> -R <repo> <file>
esac`,
	"git": `for a; do d=$a; done
case "$1 $3" in clone*) mkdir -p "$d" ;; "-C rev-parse") echo "$COMMIT" ;; esac`,
	"go": `echo "go $*" >> "$LOG"; env >> "$LOG.env"
while [ $# -gt 0 ]; do [ "$1" = -out ] && o=$2; shift; done; mkdir -p "$o" && cp "$REL"/*.tgz "$o"/`,
}

// TestSignReleaseFailsClosed runs sign-release.sh against a fake draft with a throwaway key. It publishes only when
// the key matches the committed public key, the signature verifies with it, and ci passed on the commit.
func TestSignReleaseFailsClosed(t *testing.T) {
	ms, err := exec.LookPath("minisign")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("CI needs minisign")
		}
		t.Skip("minisign not installed")
	}
	dir := t.TempDir()
	genKey := func(name string) (key, pub string) {
		key, pub = filepath.Join(dir, name+".key"), filepath.Join(dir, name+".pub")
		if b, err := exec.Command(ms, "-G", "-W", "-s", key, "-p", pub).CombinedOutput(); err != nil {
			t.Fatalf("minisign -G: %v\n%s", err, b)
		}
		return key, pub
	}
	key, pub := genKey("right")
	_, otherPub := genKey("other")
	// same key ID as the right key, other key bytes: the ID check passes and the signature check must not
	pb, _ := os.ReadFile(pub)
	lines := strings.Split(string(pb), "\n")
	raw, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil {
		t.Fatal(err)
	}
	raw[20] ^= 0xff
	lines[1] = base64.StdEncoding.EncodeToString(raw)
	forgedPub := filepath.Join(dir, "forged.pub")
	os.WriteFile(forgedPub, []byte(strings.Join(lines, "\n")), 0o644)

	rel := filepath.Join(dir, "rel")
	os.Mkdir(rel, 0o755)
	tgz := []byte("not really a tarball")
	os.WriteFile(filepath.Join(rel, "agentbox-1.0.0.tgz"), tgz, 0o644)
	os.WriteFile(filepath.Join(rel, "SHA256SUMS"), fmt.Appendf(nil, "%x  agentbox-1.0.0.tgz\n", sha256.Sum256(tgz)), 0o644)
	os.WriteFile(filepath.Join(rel, "BUILDINFO"), []byte("commit 0123abc\ngo go1.26.11\nversion 1.0.0\n"), 0o644)
	bin := filepath.Join(dir, "bin")
	os.Mkdir(bin, 0o755)
	for name, body := range signFakes {
		os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755)
	}
	script, err := os.ReadFile("sign-release.sh")
	if err != nil {
		t.Fatal(err)
	}

	run := func(t *testing.T, committed, ciRuns string) (log, env, stderr string, sig string, err error) {
		root, out := t.TempDir(), t.TempDir()
		os.MkdirAll(filepath.Join(root, "hack"), 0o755)
		os.MkdirAll(filepath.Join(root, "keys"), 0o755)
		os.WriteFile(filepath.Join(root, "hack", "sign-release.sh"), script, 0o755)
		cp, _ := os.ReadFile(committed)
		os.WriteFile(filepath.Join(root, "keys", "release-minisign.pub"), cp, 0o644)
		logf := filepath.Join(out, "log")
		cmd := exec.Command("sh", filepath.Join(root, "hack", "sign-release.sh"), "v1.0.0")
		cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "HOME="+out,
			"TMPDIR="+out, "MINISIGN_KEY="+key, "LOG="+logf, "REL="+rel, "OUT="+out, "COMMIT=0123abc", "CI_RUNS="+ciRuns)
		var e bytes.Buffer
		cmd.Stderr = &e
		err = cmd.Run()
		l, _ := os.ReadFile(logf)
		en, _ := os.ReadFile(logf + ".env")
		return string(l), string(en), e.String(), filepath.Join(out, "agentbox-1.0.0.tgz.minisig"), err
	}
	refused := func(t *testing.T, log, stderr string, err error, want string) {
		t.Helper()
		if err == nil {
			t.Fatal("exit 0, want a refusal")
		}
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr %q does not say %q", stderr, want)
		}
		if strings.Contains(log, "release upload") || strings.Contains(log, "release edit") {
			t.Errorf("refused, but still called gh to upload or publish:\n%s", log)
		}
	}

	t.Run("publishes", func(t *testing.T) {
		log, env, stderr, sig, err := run(t, pub, "1")
		if err != nil {
			t.Fatalf("%v\n%s", err, stderr)
		}
		if !strings.Contains(log, "release edit v1.0.0 -R dbabi/agentbox --draft=false") {
			t.Errorf("never published:\n%s", log)
		}
		for _, f := range []string{"--signer-workflow dbabi/agentbox/.github/workflows/release.yml", "--source-ref refs/tags/v1.0.0", "--source-digest 0123abc", "go run ./hack/release -unsigned"} {
			if !strings.Contains(log, f) {
				t.Errorf("no %q in the calls:\n%s", f, log)
			}
		}
		// the tagged code's build never sees the secret key path
		if strings.Contains(env, key) || strings.Contains(log, key) {
			t.Errorf("the rebuild got the key path %s", key)
		}
		if b, err := exec.Command(ms, "-V", "-p", pub, "-m", filepath.Join(rel, "agentbox-1.0.0.tgz"), "-x", sig).CombinedOutput(); err != nil {
			t.Errorf("uploaded signature does not verify: %v\n%s", err, b)
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		log, _, stderr, _, err := run(t, otherPub, "1")
		refused(t, log, stderr, err, "key ID")
	})
	t.Run("verify fails", func(t *testing.T) {
		log, _, stderr, _, err := run(t, forgedPub, "1")
		refused(t, log, stderr, err, "does not verify")
	})
	t.Run("no ci run", func(t *testing.T) {
		log, _, stderr, _, err := run(t, pub, "0")
		refused(t, log, stderr, err, "no successful ci workflow run")
		if strings.Contains(log, "go run") {
			t.Errorf("built before checking ci:\n%s", log)
		}
	})
}
