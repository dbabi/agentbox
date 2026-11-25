package hack

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Fake gh, git and go for sign-release.sh. gh serves the draft from $REL, logs every call, exits $ATTEST_EXIT for
// attestation verify, and counts $CI_RUNS or $RELEASE_RUNS successful push runs, none unless asked for $COMMIT; git
// clones nothing and resolves the tag to $TAG_COMMIT; go logs its arguments and environment and "builds" by copying
// CI's tarball, or by writing $REBUILD instead.
var signFakes = map[string]string{
	"gh": `echo "gh $*" >> "$LOG"
case "$1 $2" in
"release download") while [ $# -gt 0 ]; do [ "$1" = -D ] && d=$2; shift; done; mkdir -p "$d" && cp "$REL"/* "$d"/ ;;
"attestation verify") exit "$ATTEST_EXIT" ;;
"run list") for f in "--commit $COMMIT" "--event push" "--status success"; do case " $* " in *" $f "*) ;; *) echo 0; exit ;; esac; done
  case " $* " in *" --workflow ci "*) echo "$CI_RUNS" ;; *" --workflow release "*) echo "$RELEASE_RUNS" ;; *) echo 0 ;; esac ;;
"release upload") cp "$6" "$OUT"/ ;; # release upload <tag> -R <repo> <file>
esac`,
	"git": `for a; do d=$a; done
case "$1 $3" in clone*) mkdir -p "$d" ;; "-C rev-parse") echo "$TAG_COMMIT" ;; esac`,
	"go": `echo "go $*" >> "$LOG"; env >> "$LOG.env"
while [ $# -gt 0 ]; do [ "$1" = -out ] && o=$2; shift; done; mkdir -p "$o" && cp "$REL"/*.tgz "$o"/
[ -z "$REBUILD" ] || printf %s "$REBUILD" > "$o"/agentbox-1.0.0.tgz`,
}

// TestSignReleaseFailsClosed runs sign-release.sh against a fake draft with a throwaway key. It publishes only when
// the draft matches SHA256SUMS and the tag, has provenance, ci and release passed on the commit, the tag points at it,
// the rebuild is byte-identical, the key matches the committed public key, and the signature verifies with it.
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

	// a draft in its own dir, with one file changed from the good one
	draft := func(name, file string, b []byte) string {
		rel := filepath.Join(dir, name)
		os.Mkdir(rel, 0o755)
		tgz := []byte("not really a tarball")
		os.WriteFile(filepath.Join(rel, "agentbox-1.0.0.tgz"), tgz, 0o644)
		os.WriteFile(filepath.Join(rel, "SHA256SUMS"), fmt.Appendf(nil, "%x  agentbox-1.0.0.tgz\n", sha256.Sum256(tgz)), 0o644)
		os.WriteFile(filepath.Join(rel, "BUILDINFO"), []byte("commit 0123abc\ngo go1.26.11\nversion 1.0.0\n"), 0o644)
		if file != "" {
			os.WriteFile(filepath.Join(rel, file), b, 0o644)
		}
		return rel
	}
	rel := draft("rel", "", nil)
	bin := filepath.Join(dir, "bin")
	os.Mkdir(bin, 0o755)
	for name, body := range signFakes {
		os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755)
	}
	script, err := os.ReadFile("sign-release.sh")
	if err != nil {
		t.Fatal(err)
	}

	// env: KEY=value entries that override the fakes' defaults
	run := func(t *testing.T, committed string, env ...string) (log, envs, stderr string, sig string, err error) {
		root, out := t.TempDir(), t.TempDir()
		os.MkdirAll(filepath.Join(root, "hack"), 0o755)
		os.MkdirAll(filepath.Join(root, "keys"), 0o755)
		os.WriteFile(filepath.Join(root, "hack", "sign-release.sh"), script, 0o755)
		cp, _ := os.ReadFile(committed)
		os.WriteFile(filepath.Join(root, "keys", "release-minisign.pub"), cp, 0o644)
		logf := filepath.Join(out, "log")
		cmd := exec.Command("sh", filepath.Join(root, "hack", "sign-release.sh"), "v1.0.0")
		cmd.Env = append(append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "HOME="+out,
			"TMPDIR="+out, "MINISIGN_KEY="+key, "LOG="+logf, "REL="+rel, "OUT="+out, "COMMIT=0123abc", "TAG_COMMIT=0123abc",
			"ATTEST_EXIT=0", "CI_RUNS=1", "RELEASE_RUNS=1", "REBUILD="), env...)
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
		log, env, stderr, sig, err := run(t, pub)
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
	for _, c := range []struct {
		name, committed, want string
		env                   []string
		built                 bool // the check comes after the rebuild
	}{
		{"wrong key", otherPub, "key ID", nil, true},
		{"verify fails", forgedPub, "does not verify", nil, true},
		{"no ci run", pub, "no successful ci workflow run", []string{"CI_RUNS=0"}, false},
		{"no release run", pub, "no successful release workflow run", []string{"RELEASE_RUNS=0"}, false},
		{"no provenance", pub, "no valid GitHub build provenance", []string{"ATTEST_EXIT=1"}, false},
		{"tarball not in SHA256SUMS", pub, "does not match SHA256SUMS", []string{"REL=" + draft("sums", "SHA256SUMS",
			fmt.Appendf(nil, "%x  agentbox-1.0.0.tgz\n", sha256.Sum256([]byte("another tarball"))))}, false},
		{"version not the tag", pub, "BUILDINFO version 1.0.1 does not match tag v1.0.0", []string{"REL=" + draft("version",
			"BUILDINFO", []byte("commit 0123abc\ngo go1.26.11\nversion 1.0.1\n"))}, false},
		{"tag elsewhere", pub, "tag v1.0.0 does not point at 0123abc", []string{"TAG_COMMIT=4567def"}, false},
		{"rebuild differs", pub, "differs from CI's", []string{"REBUILD=another tarball"}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			log, _, stderr, _, err := run(t, c.committed, c.env...)
			refused(t, log, stderr, err, c.want)
			if !c.built && strings.Contains(log, "go run") {
				t.Errorf("built before refusing:\n%s", log)
			}
		})
	}
}

// release.yml's build job runs the tagged code (its tests, every module's init, hack/release) with a read-only token.
// Only publish may write, sign provenance and attest, so it checks out nothing and runs no Go, and it takes only
// build's three files for this commit and tag.
func TestReleaseWorkflow(t *testing.T) {
	y, err := os.ReadFile("../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	build, publish, ok := strings.Cut(string(y), "\n  publish:\n")
	if !ok {
		t.Fatal("release.yml has no publish job")
	}
	if strings.Contains(build, ": write") {
		t.Error("the workflow or its build job asks for a write permission")
	}
	for _, p := range []string{"contents: write", "id-token: write", "attestations: write"} {
		if !strings.Contains(publish, p) {
			t.Errorf("publish lacks %s", p)
		}
	}
	if regexp.MustCompile(`actions/checkout|setup-go|(?m)^ +go `).MatchString(publish) {
		t.Error("publish checks out the repo or runs Go")
	}
	m := regexp.MustCompile(`(?m)^      - name: check build's files\n        run: \|\n((?:          .*\n)+)`).FindStringSubmatch(publish)
	if m == nil {
		t.Fatal("publish has no \"check build's files\" step")
	}
	check := regexp.MustCompile(`(?m)^ {10}`).ReplaceAllString(m[1], "")
	tgz := []byte("not really a tarball")
	for _, c := range []struct {
		name string
		edit func(dist string)
		ok   bool
	}{
		{"build's files", func(string) {}, true},
		{"an extra file", func(d string) { os.WriteFile(filepath.Join(d, "agentbox-1.0.0-extra.tgz"), tgz, 0o644) }, false},
		{"a dir", func(d string) { os.Mkdir(filepath.Join(d, "x"), 0o755) }, false},
		{"no SHA256SUMS", func(d string) { os.Remove(filepath.Join(d, "SHA256SUMS")) }, false},
		{"a symlinked tarball", func(d string) {
			os.Rename(filepath.Join(d, "agentbox-1.0.0.tgz"), filepath.Join(d, "..", "elsewhere"))
			os.Symlink("../elsewhere", filepath.Join(d, "agentbox-1.0.0.tgz"))
		}, false},
		{"another commit", func(d string) {
			os.WriteFile(filepath.Join(d, "BUILDINFO"), []byte("commit 4567def\ngo go1.26.11\nversion 1.0.0\n"), 0o644)
		}, false},
		{"another version", func(d string) {
			os.WriteFile(filepath.Join(d, "BUILDINFO"), []byte("commit 0123abc\ngo go1.26.11\nversion 1.0.1\n"), 0o644)
		}, false},
		{"a second commit line", func(d string) {
			os.WriteFile(filepath.Join(d, "BUILDINFO"), []byte("commit 0123abc\ngo go1.26.11\nversion 1.0.0\ncommit 4567def\n"), 0o644)
		}, false},
		{"a changed tarball", func(d string) { os.WriteFile(filepath.Join(d, "agentbox-1.0.0.tgz"), []byte("other"), 0o644) }, false},
		{"SHA256SUMS of another file", func(d string) {
			b, _ := os.ReadFile(filepath.Join(d, "BUILDINFO"))
			os.WriteFile(filepath.Join(d, "SHA256SUMS"), fmt.Appendf(nil, "%x  BUILDINFO\n", sha256.Sum256(b)), 0o644)
		}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			d := filepath.Join(root, "dist")
			os.Mkdir(d, 0o755)
			os.WriteFile(filepath.Join(d, "agentbox-1.0.0.tgz"), tgz, 0o644)
			os.WriteFile(filepath.Join(d, "SHA256SUMS"), fmt.Appendf(nil, "%x  agentbox-1.0.0.tgz\n", sha256.Sum256(tgz)), 0o644)
			os.WriteFile(filepath.Join(d, "BUILDINFO"), []byte("commit 0123abc\ngo go1.26.11\nversion 1.0.0\n"), 0o644)
			c.edit(d)
			cmd := exec.Command("bash", "-e", "-c", check) // a run step's default shell
			cmd.Dir, cmd.Env = root, append(os.Environ(), "GITHUB_REF_NAME=v1.0.0", "GITHUB_SHA=0123abc")
			if out, err := cmd.CombinedOutput(); (err == nil) != c.ok {
				t.Errorf("check exited %v, want ok=%v:\n%s", err, c.ok, out)
			}
		})
	}
}
