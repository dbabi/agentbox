package rootd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"agentbox/internal/ids"
)

// secret.set (#108): the value goes to the encrypter on its own, into the owning service's dir by rename, never into
// audit, a reply or the journal; the INTENT names only the credential; the owning unit restarts; a name the box
// doesn't know or a value that isn't one short line changes nothing.
func TestSecretSet(t *testing.T) {
	dir := t.TempDir()
	var recs []map[string]any
	var enc, restarts []string
	s := &server{cfg: Config{CredStore: dir,
		Encrypt: func(name, value, out string) error {
			enc = append(enc, name+"="+value)
			return os.WriteFile(out, []byte("ENC:"+name), 0o644)
		},
		Restart: func(unit string, ifRunning bool) error {
			restarts = append(restarts, unit+" "+map[bool]string{true: "try", false: "now"}[ifRunning])
			return nil
		}},
		audit: func(r map[string]any) error { recs = append(recs, r); return nil }}
	const v = "sk-ant-api03-SECRETVALUE"
	rep := s.secretSet(request{Op: "secret.set", Name: "anthropic-api-key", Value: ptr(v)})
	if rep["ok"] != true || rep["service"] != "agentbox-keys" {
		t.Fatalf("secret.set: %v", rep)
	}
	b, err := os.ReadFile(filepath.Join(dir, "keys", "anthropic-api-key"))
	fi, _ := os.Stat(filepath.Join(dir, "keys", "anthropic-api-key"))
	if err != nil || string(b) != "ENC:anthropic-api-key" || fi.Mode().Perm() != 0o600 || !slices.Equal(enc, []string{"anthropic-api-key=" + v}) {
		t.Fatalf("stored %q %v %v %v", b, err, fi.Mode(), enc)
	}
	if !slices.Equal(restarts, []string{"agentbox-keys.service try"}) {
		t.Errorf("restarts %v", restarts)
	}
	all, _ := json.Marshal(append(recs, rep))
	if strings.Contains(string(all), "SECRETVALUE") {
		t.Errorf("the value reached audit or the reply: %s", all)
	}
	if len(recs) != 2 || recs[0]["type"] != "INTENT" || recs[0]["name"] != "secret.set" || recs[1]["type"] != "RESULT" || recs[1]["status"] != "executed" {
		t.Errorf("audit %v", recs)
	}
	if m, _ := recs[0]["args"].(map[string]string); len(m) != 1 || m["name"] != "anthropic-api-key" {
		t.Errorf("INTENT args %v", recs[0]["args"])
	}
	for _, r := range []request{{Name: "aws-key", Value: ptr("x")}, {Name: "openai-api-key"}, {Name: "openai-api-key", Value: ptr("")},
		{Name: "openai-api-key", Value: ptr("a\nb")}, {Name: "openai-api-key", Value: ptr(strings.Repeat("x", MaxSecret+1))}} {
		if rep := s.secretSet(r); rep["ok"] != false || strings.Contains(rep["error"].(string), "a\nb") {
			t.Errorf("%s accepted: %v", r.Name, rep)
		}
	}
	if len(recs) != 2 || len(enc) != 1 {
		t.Errorf("a refused secret.set still ran: %d records, %d encryptions", len(recs), len(enc))
	}
	// the placeholders: every credential gets one until secret.set, and an existing one is left alone
	s.ensureCreds()
	for name, svc := range Credentials {
		if _, err := os.Stat(filepath.Join(dir, svc, name)); err != nil {
			t.Errorf("no placeholder for %s: %v", name, err)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "keys", "anthropic-api-key")); string(b) != "ENC:anthropic-api-key" || len(enc) != 3 || !slices.Contains(enc, "github-token=") {
		t.Errorf("ensureCreds: %q %v", b, enc)
	}
	// the key: the TPM2 with no PCRs when /etc/crypttab holds the LUKS root (tpm2 modes), the host key otherwise
	ct := filepath.Join(dir, "crypttab")
	os.WriteFile(ct, []byte("# none\n\n"), 0o644)
	if a := credKeyArgs(ct); !slices.Equal(a, []string{"--with-key=host"}) {
		t.Errorf("none mode: %v", a)
	}
	os.WriteFile(ct, []byte("root UUID=x none luks,discard\n"), 0o644)
	if a := credKeyArgs(ct); !slices.Equal(a, []string{"--with-key=tpm2", "--tpm2-pcrs="}) {
		t.Errorf("tpm2 mode: %v", a)
	}
}

func ptr(s string) *string { return &s }

// llm.recycle restarts the local LLM at most once a minute; task.tainted is auditd's effective taint of a live task.
func TestLLMRecycleAndTaint(t *testing.T) {
	var at []time.Time
	r := newRig(t)
	s := &server{tasks: r.t, cfg: Config{Restart: func(unit string, ifRunning bool) error {
		if unit != LLMUnit || ifRunning {
			t.Errorf("restart %s %v", unit, ifRunning)
		}
		at = append(at, time.Now())
		return nil
	}}}
	if rep := s.llmRecycle(); rep["ok"] != true {
		t.Fatal(rep)
	}
	s.llm.last = time.Now().Add(-59*time.Second - 700*time.Millisecond) // as if the first restart was 59.3 s ago
	if rep := s.llmRecycle(); rep["ok"] != true || len(at) != 2 || at[1].Sub(at[0]) < 250*time.Millisecond {
		t.Errorf("a second recycle inside the minute did not wait: %v", at)
	}
	id := ids.New(ids.Task)
	req, _ := r.t.newRequest("boxadmin", "claude", 3, time.Hour)
	if rep := r.t.start(id, "claude", "admin:"+req); rep["ok"] != true {
		t.Fatal(rep)
	}
	if rep := s.taskTainted(id); rep["ok"] != true || rep["tainted"] != false {
		t.Errorf("clean: %v", rep)
	}
	r.wsTaint = true
	if rep := s.taskTainted(id); rep["tainted"] != true {
		t.Errorf("tainted workspace: %v", rep)
	}
	if rep := s.taskTainted(ids.New(ids.Task)); rep["ok"] != false {
		t.Errorf("a task that isn't live: %v", rep)
	}
}

// keys gets the task's trace at register and in task.list_live (§6.3); the other services' calls stay as they were.
func TestKeysTrace(t *testing.T) {
	r := newRig(t)
	var regs []string
	r.t.cfg.Svc = func(svc string, req map[string]any) (map[string]any, error) {
		if req["call"] == "register" {
			_, has := req["trace"]
			regs = append(regs, svc+" "+map[bool]string{true: "trace", false: "-"}[has])
		}
		return map[string]any{"ok": true}, nil
	}
	id := ids.New(ids.Task)
	req, _ := r.t.newRequest("boxadmin", "claude", 3, time.Hour)
	rep := r.t.start(id, "claude", "admin:"+req)
	if rep["ok"] != true || !slices.Equal(regs, []string{"gate -", "proxy -", "keys trace", "git -"}) {
		t.Fatalf("start %v, registers %v", rep, regs)
	}
	b, _ := json.Marshal(r.t.listLive())
	if !strings.Contains(string(b), `"trace":"`+rep["trace"].(string)+`"`) {
		t.Errorf("task.list_live: %s", b)
	}
}
