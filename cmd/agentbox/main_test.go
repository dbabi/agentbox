package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agentbox/internal/recovery"
)

func TestFlagParsing(t *testing.T) {
	if err := run([]string{"seed", "-h"}); !errors.Is(err, flag.ErrHelp) {
		t.Errorf("seed -h: %v", err)
	}
	if err := run([]string{"seed", "--nope"}); !errors.Is(err, errUsage) {
		t.Errorf("seed --nope: %v", err)
	}
	out := filepath.Join(t.TempDir(), "seed")
	err := run([]string{"seed", "--encryption", "none", "--out", out, "stray", "--boot", "bios"})
	if err == nil || !strings.Contains(err.Error(), `"stray"`) {
		t.Fatalf("stray positional accepted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "user-data")); err == nil {
		t.Fatal("user-data written despite the error")
	}
}

func TestDecryptRefusesExistingOutput(t *testing.T) {
	dir := t.TempDir()
	priv, pub, err := recovery.GenerateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, _ := os.ReadFile(pub)
	pk, err := recovery.ParsePublic(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := recovery.Encrypt(pk, []byte("012345678901234567890123456789012345678901234567"))
	bin, existing := filepath.Join(dir, "recovery.bin"), filepath.Join(dir, "luks.key")
	os.WriteFile(bin, ct, 0o600)
	os.WriteFile(existing, []byte("keep"), 0o600)
	if err := run([]string{"recovery", "decrypt", "--key", priv, "--in", bin, "--out", existing}); err == nil {
		t.Fatal("decrypt overwrote an existing file")
	}
	if b, _ := os.ReadFile(existing); string(b) != "keep" {
		t.Fatal("existing file changed")
	}
}

func edLine(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	str := func(b []byte) []byte {
		l := make([]byte, 4)
		binary.BigEndian.PutUint32(l, uint32(len(b)))
		return append(l, b...)
	}
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(append(str([]byte("ssh-ed25519")), str(pub)...)) + " k@laptop"
}

// The default flags must render an installable seed: this is the case that would have caught the reserved `admin`.
func TestSeedDefaultsRender(t *testing.T) {
	_, pub, err := recovery.GenerateKey(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	k1, k2 := edLine(t), edLine(t)
	out := filepath.Join(t.TempDir(), "seed")
	err = run([]string{"seed", "--disk-serial", "QEMU_NVMe_Ctrl_QM00001_1", "--ssh-key", k1, "--ssh-key", k2,
		"--password-hash", "$6$saltsalt$" + strings.Repeat("a", 85) + "0", "--minisign-pubkey", "RWQ" + strings.Repeat("A", 53),
		"--release-url", "https://releases.example.com/a.tgz", "--tang-url", "http://192.168.1.10:7500",
		"--tang-thp", "_OsIk0T-E2l6qjfdDiwVmidoZjA", "--recovery-pub", pub, "--out", out})
	if err != nil {
		t.Fatal(err)
	}
	ud, err := os.ReadFile(filepath.Join(out, "user-data"))
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{`username: "boxadmin"`, k1, k2, "# encryption=tpm2+tang boot=uefi"} {
		if !strings.Contains(string(ud), w) {
			t.Errorf("default seed lacks %q", w)
		}
	}
}

func TestRecoveryHelp(t *testing.T) {
	for _, a := range []string{"-h", "--help", "help"} {
		if err := run([]string{"recovery", a}); !errors.Is(err, flag.ErrHelp) {
			t.Errorf("recovery %s: %v", a, err)
		}
	}
}

// TestOSArgs checks `agentbox os` argument handling before anything touches the box.
func TestOSArgs(t *testing.T) {
	t.Setenv("AGENTBOX_OS_NS", "1") // skip the re-exec into a private mount namespace
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"os"}, "expected plan, apply"},
		{[]string{"os", "apply"}, "--approve needs the plan's sha256"},
		{[]string{"os", "apply", "--approve", strings.Repeat("A", 64)}, "--approve needs the plan's sha256"},
		{[]string{"os", "apply", "--approve", strings.Repeat("a", 63)}, "--approve needs the plan's sha256"},
		{[]string{"os", "plan"}, "at least one --install or --remove"},
		{[]string{"os", "plan", "--install", "systemd", "stray"}, `unexpected argument "stray"`},
		{[]string{"os", "frobnicate"}, `unknown subcommand "frobnicate"`},
	} {
		if err := run(tc.args); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v, want %q", tc.args, err, tc.want)
		}
	}
	if err := run([]string{"os", "--help"}); !errors.Is(err, flag.ErrHelp) {
		t.Errorf("os --help: %v", err)
	}
}
