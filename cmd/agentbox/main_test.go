package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"agentbox/internal/gate"
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
		"--password-hash", "$y$j9T$agentboxgatesalt0000$nVjZH1ZaNBH.vEdKjhLQLZVUy6bJDJKQOxEO8qRil23", "--minisign-pubkey", "RWQ" + strings.Repeat("A", 53),
		"--release-url", "https://releases.example.com/a.tgz", "--tang-url", "http://192.168.1.10:7500",
		"--tang-thp", "_OsIk0T-E2l6qjfdDiwVmidoZjA", "--recovery-pub", pub, "--out", out, "--release-sha256", strings.Repeat("0a", 32)})
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

// A gate request near MaxRequest full of '<' stays within rootd.sock's line: forwarded args are copied, not escaped.
func TestEncodeLineCopiesArgs(t *testing.T) {
	args := json.RawMessage(`{"path":"/srv/a/x","content":"` + strings.Repeat("<", gate.MaxRequest-100) + `"}`)
	b := encodeLine(map[string]any{"op": "task.op", "name": "file.write", "args": args, "task": "T1", "agent": "a", "chain": []string{}})
	if len(b) > len(args)+200 || !strings.Contains(string(b), string(args)) || b[len(b)-1] != '\n' {
		t.Fatalf("line of %d bytes for %d bytes of args", len(b), len(args))
	}
}

// #213: task new bounds the prompt as its request line carries it: '<' counts 1 byte and a newline 2. At gate.MaxPrompt
// the CLI goes on to rootd-admin.sock; one newline more is refused first, naming the limit.
func TestTaskNewPromptLimit(t *testing.T) {
	p := strings.Repeat("<<<<<<<<<\n", gate.MaxPrompt/11-1) // 11 bytes each as JSON
	p += strings.Repeat("<", gate.MaxPrompt-gate.PromptLen(p))
	stdin := os.Stdin
	defer func() { os.Stdin = stdin }()
	for _, tc := range []struct {
		prompt string
		over   bool
	}{{p, false}, {p + "\n", true}} {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		go func() { w.WriteString(tc.prompt); w.Close() }()
		os.Stdin = r
		err = run([]string{"task", "new", "--agent", "a"})
		r.Close()
		if over := err != nil && strings.Contains(err.Error(), "over 64512 bytes as JSON"); over != tc.over || err == nil {
			t.Fatalf("a prompt of %d bytes as JSON: %v", gate.PromptLen(tc.prompt), err)
		}
	}
}

// #198: an error or reply rootd sends can carry names a task chose; the CLI prints it with every terminal control
// escaped, and a JSON reply still decodes to the same value.
func TestPrintable(t *testing.T) {
	in := "refused: \"a\\x1b[2K\" b\x1b]52;c;ZXZpbA==\x07 c\u202ed\u009b\nline 2\tx é\U000e0001"
	want := `refused: "a\x1b[2K" b\u001b]52;c;ZXZpbA==\u0007 c\u202ed\u009b` + "\nline 2\tx é" + `\udb40\udc01`
	if got := printable(in); got != want {
		t.Fatalf("printable(%q) = %q, want %q", in, got, want)
	}
	hits := map[string]string{"path": "notes/a\u009b2J\u202eb\U000e0001"}
	line, _ := json.Marshal(hits)
	var back map[string]string
	if out := printable(string(line)); strings.ContainsAny(out, "\u009b\u202e\U000e0001") || json.Unmarshal([]byte(out), &back) != nil || back["path"] != hits["path"] {
		t.Fatalf("printable(%s) = %s: decodes to %q", line, out, back)
	}
}

// #213: fwcheck --repair, os health and os apply send their ALERTs to ntfy's alert topic with fixed text. A keyed
// condition goes out once, and again after alertClear; a send that fails leaves it to the next run.
func TestAlert(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "alert") // sun_path is 104 bytes on macOS: t.TempDir is too long
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock, tok, marks := alertSock, alertToken, alertDir
	defer func() { alertSock, alertToken, alertDir = sock, tok, marks }()
	alertSock, alertToken, alertDir = filepath.Join(dir, "ntfy.sock"), filepath.Join(dir, "token"), filepath.Join(dir, "alerts")
	if err := os.WriteFile(alertToken, []byte("tk_x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	alert("firewall", "agentbox: firewall", "down") // ntfy isn't up yet
	if _, err := os.Stat(filepath.Join(alertDir, "firewall")); err == nil {
		t.Fatal("a failed send marked the condition as alerted")
	}
	var mu sync.Mutex
	var got []string
	l, err := net.Listen("unix", alertSock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, r.URL.Path+" "+r.Header.Get("Authorization")+" "+r.Header.Get("Title")+": "+string(b))
		mu.Unlock()
	})}
	go srv.Serve(l)
	defer srv.Close()
	alert("firewall", "agentbox: firewall", "altered")
	alert("firewall", "agentbox: firewall", "altered") // the next health run: still altered
	alert("", "agentbox: os apply", "discarded")
	alert("", "agentbox: os apply", "discarded")
	alertClear("firewall")
	alert("firewall", "agentbox: firewall", "altered")
	mu.Lock()
	defer mu.Unlock()
	f, o := "/agentbox-alerts Bearer tk_x agentbox: firewall: altered", "/agentbox-alerts Bearer tk_x agentbox: os apply: discarded"
	if want := []string{f, o, o, f}; !slices.Equal(got, want) {
		t.Fatalf("sent %q, want %q", got, want)
	}
}

// #218: fwcheck --repair also repairs a failed agentbox-firewall.service, since a failed load stopped every unit that
// Requires= it, even once the table checks out. After the restart it starts those units, rootd first. A failed
// restart starts nothing. Without --repair, fwcheck only checks.
func TestFWCheckRepair(t *testing.T) {
	dir := t.TempDir()
	check, ctl, marks, sock, tok := fwCheck, systemctl, alertDir, alertSock, alertToken
	defer func() { fwCheck, systemctl, alertDir, alertSock, alertToken = check, ctl, marks, sock, tok }()
	alertDir, alertSock, alertToken = filepath.Join(dir, "alerts"), filepath.Join(dir, "none"), filepath.Join(dir, "token") // no ntfy
	all := [][]string{{"restart", "agentbox-firewall.service"}, {"start", "agentbox-rootd.service"},
		{"start", "agentbox-auditd.service", "agentboxd.service", "ntfy.service"}}
	for _, tc := range []struct {
		name                          string
		altered, failed, restartFails bool
		want                          [][]string
	}{
		{"intact", false, false, false, nil},
		{"an altered table", true, false, false, all},
		{"a failed unit, an intact table", false, true, false, all},
		{"a restart that fails", true, false, true, all[:1]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls [][]string
			restarted := false
			fwCheck = func() ([]string, error) {
				if tc.altered && !restarted {
					return []string{"set confined: missing element 70001-70999"}, nil
				}
				return nil, nil
			}
			systemctl = func(args ...string) ([]byte, error) {
				if args[0] == "is-failed" {
					if tc.failed {
						return nil, nil
					}
					return nil, errors.New("exit status 1")
				}
				calls = append(calls, args)
				if args[0] == "restart" && tc.restartFails {
					return []byte("Job for agentbox-firewall.service failed."), errors.New("exit status 1")
				}
				restarted = restarted || args[0] == "restart"
				return nil, nil
			}
			err := cmdFWCheck([]string{"--repair"})
			if (err == nil) != !tc.restartFails || !slices.EqualFunc(calls, tc.want, slices.Equal[[]string]) {
				t.Fatalf("err %v, systemctl %q; want %q", err, calls, tc.want)
			}
		})
	}
	systemctl = func(args ...string) ([]byte, error) { t.Errorf("systemctl %q without --repair", args); return nil, nil }
	fwCheck = func() ([]string, error) { return []string{"altered"}, nil }
	if err := cmdFWCheck(nil); err == nil {
		t.Error("fwcheck passed an altered table")
	}
}
