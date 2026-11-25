package hack

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Fake gh, git, go, sudo and ps for sign-release.sh. gh serves the draft from $REL, logs every call, exits $ATTEST_EXIT
// for attestation verify, and counts $CI_RUNS or $RELEASE_RUNS successful push runs, none unless asked for $COMMIT;
// git clones only a .clone file that names the clone's path, and resolves the tag to $TAG_COMMIT; go logs its arguments
// and environment and "builds" by copying CI's tarball, or by writing $REBUILD instead (with $SWAP, over CI's own copy
// too), and exits $GO_EXIT. sudo stands in for the build user, the user nobody: while the command runs, $KEYFILE can't
// be read and $BIN can't be written, and ps shows the command on a terminal of its own; $SHARE lists what it shares
// with you instead.
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
case "$1 $3" in clone*) mkdir -p "$d" && echo "$d" > "$d/.clone" ;; "-C rev-parse") echo "$TAG_COMMIT" ;; esac`,
	"go": `echo "go $*" >> "$LOG"; env >> "$LOG.env"
[ -f .clone ] && echo "go: in a copy of the clone" >> "$LOG"
while [ $# -gt 0 ]; do [ "$1" = -out ] && o=$2; shift; done; mkdir -p "$o" && cp "$REL"/*.tgz "$o"/
[ -z "$REBUILD" ] || printf %s "$REBUILD" > "$o"/agentbox-1.0.0.tgz
[ -z "$SWAP" ] || printf %s "$REBUILD" > "$(dirname "$(cat .clone)")"/ci/agentbox-1.0.0.tgz
exit "${GO_EXIT:-0}"`,
	"sudo": `echo "sudo $1 $2 $3 $4 $5" >> "$LOG" # not the script after them, which names go run
[ "$1 $2 $3 $4" = "-u nobody env -i" ] || exit 1
shift 4
case " $SHARE " in *" key "*) ;; *) chmod 0 "$KEYFILE" ;; esac
case " $SHARE " in *" bin "*) ;; *) chmod a-w "$BIN" ;; esac
case " $SHARE " in *" tty "*) t=$FAKE_TTY ;; *) t=pts/9 ;; esac
env -i FAKE_TTY="$t" LOG="$LOG" REL="$REL" REBUILD="$REBUILD" SWAP="$SWAP" GO_EXIT="$GO_EXIT" "$@"; r=$?
chmod 600 "$KEYFILE"; chmod 755 "$BIN"
exit $r`,
	"ps": `echo "$FAKE_TTY"`,
}

// TestSignReleaseFailsClosed runs sign-release.sh against a fake draft with a throwaway key. It publishes only when
// the draft matches SHA256SUMS and the tag, has provenance, ci and release passed on the commit, the tag points at it,
// the rebuild is byte-identical, the key matches the committed public key, and the signature verifies with it. The
// rebuild runs through sudo as the build user, and only if that user can't read the key, write a directory on PATH or
// use your terminal; it gets a copy of the clone and none of your environment.
func TestSignReleaseFailsClosed(t *testing.T) {
	ms, err := exec.LookPath("minisign")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("CI needs minisign")
		}
		t.Skip("minisign not installed")
	}
	if os.Getuid() == 0 {
		t.Skip("root reads any file, so the fake sudo's chmod can't stand in for another user")
	}
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
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

	rel := signDraft(t, dir, "rel", "", nil)
	script, err := os.ReadFile("sign-release.sh")
	if err != nil {
		t.Fatal(err)
	}

	// env: KEY=value entries that override the fakes' defaults
	run := func(t *testing.T, committed string, env ...string) (log, envs, stderr string, sig string, err error) {
		root, out, bin := t.TempDir(), t.TempDir(), t.TempDir()
		for name, body := range signFakes {
			os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755)
		}
		// a PATH with no directory that this user can write but bin, which the fake sudo locks
		os.Symlink(ms, filepath.Join(bin, "minisign"))
		os.MkdirAll(filepath.Join(root, "hack"), 0o755)
		os.MkdirAll(filepath.Join(root, "keys"), 0o755)
		os.WriteFile(filepath.Join(root, "hack", "sign-release.sh"), script, 0o755)
		cp, _ := os.ReadFile(committed)
		os.WriteFile(filepath.Join(root, "keys", "release-minisign.pub"), cp, 0o644)
		logf := filepath.Join(out, "log")
		cmd := exec.Command("sh", filepath.Join(root, "hack", "sign-release.sh"), "v1.0.0")
		cmd.Env = append(append(os.Environ(), "PATH="+bin+":/usr/bin:/bin:/usr/sbin:/sbin", "HOME="+out, "TMPDIR="+out,
			"MINISIGN_KEY="+key, "AGENTBOX_BUILD_USER=nobody", "KEYFILE="+key, "BIN="+bin, "FAKE_TTY=pts/1", "SHARE=",
			"LOG="+logf, "REL="+rel, "OUT="+out, "COMMIT=0123abc", "TAG_COMMIT=0123abc", "ATTEST_EXIT=0", "CI_RUNS=1",
			"RELEASE_RUNS=1", "REBUILD=", "SWAP=", "GO_EXIT="), env...)
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
		for _, f := range []string{"--signer-workflow dbabi/agentbox/.github/workflows/release.yml", "--source-ref refs/tags/v1.0.0",
			"--source-digest 0123abc", "sudo -u nobody env -i PATH=", "go run ./hack/release -unsigned", "go: in a copy of the clone"} {
			if !strings.Contains(log, f) {
				t.Errorf("no %q in the calls:\n%s", f, log)
			}
		}
		// the tagged code's build gets none of your environment: not the key path, your HOME or the fakes' settings
		for _, s := range []string{key, "HOME=" + filepath.Dir(sig) + "\n", "TAG_COMMIT="} {
			if strings.Contains(env, s) {
				t.Errorf("the rebuild's environment has %q:\n%s", s, env)
			}
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
		{"tarball not in SHA256SUMS", pub, "does not match SHA256SUMS", []string{"REL=" + signDraft(t, dir, "sums", "SHA256SUMS",
			fmt.Appendf(nil, "%x  agentbox-1.0.0.tgz\n", sha256.Sum256([]byte("another tarball"))))}, false},
		{"version not the tag", pub, "BUILDINFO version 1.0.1 does not match tag v1.0.0", []string{"REL=" + signDraft(t, dir, "version",
			"BUILDINFO", []byte("commit 0123abc\ngo go1.26.11\nversion 1.0.1\n"))}, false},
		{"tag elsewhere", pub, "tag v1.0.0 does not point at 0123abc", []string{"TAG_COMMIT=4567def"}, false},
		{"rebuild differs", pub, "differs from CI's", []string{"REBUILD=another tarball"}, true},
		{"rebuild fails", pub, "the rebuild as nobody failed", []string{"GO_EXIT=1"}, true},
		// the tagged code writes its bytes over CI's tarball too: only the hash taken before the rebuild tells them apart
		{"rebuild rewrites CI's tarball", pub, "differs from CI's", []string{"REBUILD=another tarball", "SWAP=1"}, true},
		{"no build user", pub, "no user no-such-user-216", []string{"AGENTBOX_BUILD_USER=no-such-user-216"}, false},
		{"build user is you", pub, "is root or you", []string{"AGENTBOX_BUILD_USER=" + me.Username}, false},
		{"build user reads the key", pub, "can read " + key, []string{"SHARE=key"}, false},
		{"build user writes PATH", pub, "can write ", []string{"SHARE=bin"}, false},
		{"build user on your terminal", pub, "runs on your terminal", []string{"SHARE=tty"}, false},
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

// signDraft writes a draft in its own dir, with one file changed from the good one.
func signDraft(t *testing.T, dir, name, file string, b []byte) string {
	t.Helper()
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

// TestSignReleaseBuildUser runs sign-release.sh with the real sudo, where it can run commands as the user nobody with
// no password (CI). The fake go runs there as the tagged code would, and tries to read the key and to put a fake
// minisign on PATH; neither works, and the release publishes. With the key readable by that user, the script refuses
// before the rebuild.
func TestSignReleaseBuildUser(t *testing.T) {
	ms, err := exec.LookPath("minisign")
	if err == nil && exec.Command("sudo", "-n", "-u", "nobody", "true").Run() != nil {
		err = fmt.Errorf("sudo can't run commands as nobody without a password")
	}
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI needs minisign, and sudo to nobody with no password: %v", err)
		}
		t.Skip(err)
	}
	keys, bin, rel, out := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	// the user nobody may reach bin and the draft, not the key or this test's output
	for _, d := range []string{filepath.Dir(bin), bin, rel} {
		os.Chmod(d, 0o755)
	}
	key, pub := filepath.Join(keys, "k.key"), filepath.Join(keys, "k.pub")
	if b, err := exec.Command(ms, "-G", "-W", "-s", key, "-p", pub).CombinedOutput(); err != nil {
		t.Fatalf("minisign -G: %v\n%s", err, b)
	}
	tgz := []byte("not really a tarball")
	os.WriteFile(filepath.Join(rel, "agentbox-1.0.0.tgz"), tgz, 0o644)
	os.WriteFile(filepath.Join(rel, "SHA256SUMS"), fmt.Appendf(nil, "%x  agentbox-1.0.0.tgz\n", sha256.Sum256(tgz)), 0o644)
	os.WriteFile(filepath.Join(rel, "BUILDINFO"), []byte("commit 0123abc\ngo go1.26.11\nversion 1.0.0\n"), 0o644)
	os.WriteFile(filepath.Join(bin, "gh"), []byte("#!/bin/sh\n"+signFakes["gh"]+"\n"), 0o755)
	os.WriteFile(filepath.Join(bin, "git"), []byte("#!/bin/sh\n"+signFakes["git"]+"\n"), 0o755)
	os.WriteFile(filepath.Join(bin, "go"), fmt.Appendf(nil, `#!/bin/sh
echo "rebuild: runs as $(id -un)" >&2
cat %[1]q >/dev/null 2>&1 && echo "rebuild: read the key" >&2
touch %[2]q/minisign 2>/dev/null && echo "rebuild: put a minisign on PATH" >&2
while [ $# -gt 0 ]; do [ "$1" = -out ] && o=$2; shift; done; mkdir -p "$o" && cp %[3]q/agentbox-1.0.0.tgz "$o"/
`, key, bin, rel), 0o755)
	root := filepath.Join(out, "checkout")
	os.MkdirAll(filepath.Join(root, "hack"), 0o755)
	os.MkdirAll(filepath.Join(root, "keys"), 0o755)
	script, _ := os.ReadFile("sign-release.sh")
	os.WriteFile(filepath.Join(root, "hack", "sign-release.sh"), script, 0o755)
	cp, _ := os.ReadFile(pub)
	os.WriteFile(filepath.Join(root, "keys", "release-minisign.pub"), cp, 0o644)
	run := func() (string, error) {
		cmd := exec.Command("sh", filepath.Join(root, "hack", "sign-release.sh"), "v1.0.0")
		cmd.Dir = "/" // the user nobody may not be able to open this test's working directory
		cmd.Env = append(os.Environ(), "PATH="+bin+":/usr/bin:/bin", "HOME="+out, "TMPDIR="+out, "MINISIGN_KEY="+key,
			"AGENTBOX_BUILD_USER=nobody", "LOG="+filepath.Join(out, "log"), "REL="+rel, "OUT="+out, "COMMIT=0123abc",
			"TAG_COMMIT=0123abc", "ATTEST_EXIT=0", "CI_RUNS=1", "RELEASE_RUNS=1")
		b, err := cmd.CombinedOutput()
		return string(b), err
	}
	b, err := run()
	if err != nil || !strings.Contains(b, "rebuild: runs as nobody") || strings.Contains(b, "rebuild: read") || strings.Contains(b, "rebuild: put") {
		t.Fatalf("%v\n%s", err, b)
	}
	if b, err := exec.Command(ms, "-V", "-p", pub, "-m", filepath.Join(rel, "agentbox-1.0.0.tgz"), "-x", filepath.Join(out, "agentbox-1.0.0.tgz.minisig")).CombinedOutput(); err != nil {
		t.Errorf("uploaded signature does not verify: %v\n%s", err, b)
	}
	os.Chmod(keys, 0o755)
	os.Chmod(key, 0o644)
	if b, err := run(); err == nil || !strings.Contains(b, "nobody can read "+key) || strings.Contains(b, "rebuild: runs") {
		t.Errorf("a key that the user nobody can read: %v\n%s", err, b)
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
