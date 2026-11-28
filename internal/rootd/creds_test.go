package rootd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"agentbox/internal/canary"
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
		Encrypt: func(name, value string) ([]byte, error) {
			enc = append(enc, name+"="+value)
			return []byte("ENC:" + name), nil
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
	if left, _ := filepath.Glob(filepath.Join(dir, "keys", ".*")); len(left) != 0 {
		t.Errorf("temp files left: %v", left)
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
	// the value on stdin, the ciphertext on stdout: rootd writes the file itself (#313)
	if a := encryptArgs("github-token", ct); !slices.Equal(a, []string{"encrypt", "--name=github-token", "--with-key=tpm2", "--tpm2-pcrs=", "-", "-"}) {
		t.Errorf("argv %q", a)
	}
}

// Concurrent secret.set calls for one name run one at a time through their restart (#313): each restart loads the
// value its own call stored, so every call's ok reply is true of the stored credential, and the last call's value is
// what stays. Each write goes through its own temp file, so no call fails on another's.
func TestSecretSetConcurrent(t *testing.T) {
	dir := t.TempDir()
	var mu sync.Mutex
	var events []string // "enc V" and "load V": what each encryption made, and what each restart found stored
	cred := filepath.Join(dir, "keys", "anthropic-api-key")
	s := &server{cfg: Config{CredStore: dir,
		Encrypt: func(name, value string) ([]byte, error) {
			mu.Lock()
			events = append(events, "enc "+value)
			mu.Unlock()
			time.Sleep(time.Millisecond) // let another call in, if anything lets it
			return []byte("ENC:" + value), nil
		},
		Restart: func(unit string, ifRunning bool) error {
			b, _ := os.ReadFile(cred)
			mu.Lock()
			events = append(events, "load "+strings.TrimPrefix(string(b), "ENC:"))
			mu.Unlock()
			return nil
		}},
		audit: func(map[string]any) error { return nil }}
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rep := s.secretSet(request{Op: "secret.set", Name: "anthropic-api-key", Value: ptr(fmt.Sprintf("sk-ant-api03-V%02d", i))}); rep["ok"] != true || rep["restarted"] != true {
				t.Errorf("call %d: %v", i, rep)
			}
		}()
	}
	wg.Wait()
	if len(events) != 32 {
		t.Fatalf("events %q", events)
	}
	for i := 0; i < len(events); i += 2 {
		v, ok := strings.CutPrefix(events[i], "enc ")
		if !ok || events[i+1] != "load "+v {
			t.Fatalf("a restart did not load its own call's value: %q", events)
		}
	}
	b, _ := os.ReadFile(cred)
	if last := strings.TrimPrefix(events[len(events)-1], "load "); string(b) != "ENC:"+last {
		t.Errorf("stored %q, the last call stored %q", b, last)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "keys", ".*")); len(left) != 0 {
		t.Errorf("temp files left: %v", left)
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
// The gate, keys and git get the task's canary at register (#105, #291); the proxy never does.
func TestKeysTrace(t *testing.T) {
	r := newRig(t)
	var regs []string
	r.t.cfg.Svc = func(svc string, req map[string]any) (map[string]any, error) {
		if req["call"] == "register" {
			_, has := req["trace"]
			c, _ := req["canary"].(string)
			regs = append(regs, svc+" "+map[bool]string{true: "trace", false: "-"}[has]+" "+map[bool]string{true: "canary", false: "-"}[canary.Valid(c)])
		}
		return map[string]any{"ok": true}, nil
	}
	id := ids.New(ids.Task)
	req, _ := r.t.newRequest("boxadmin", "claude", 3, time.Hour)
	rep := r.t.start(id, "claude", "admin:"+req)
	if rep["ok"] != true || !slices.Equal(regs, []string{"gate - canary", "proxy - -", "keys trace canary", "git - canary"}) {
		t.Fatalf("start %v, registers %v", rep, regs)
	}
	b, _ := json.Marshal(r.t.listLive(false))
	if !strings.Contains(string(b), `"trace":"`+rep["trace"].(string)+`"`) {
		t.Errorf("task.list_live: %s", b)
	}
}

// Each broker unit loads exactly the credentials secret.set gives its service, from that service's dir in the store,
// and no other unit loads any (#108).
func TestUnitCredentials(t *testing.T) {
	want := map[string][]string{}
	for name, svc := range Credentials {
		want["agentbox-"+svc+".service"] = append(want["agentbox-"+svc+".service"], "LoadCredentialEncrypted="+name+":"+CredStore+"/"+svc+"/"+name)
	}
	units, _ := filepath.Glob("../../systemd/*.service")
	if len(units) == 0 {
		t.Fatal("no units")
	}
	for _, u := range units {
		b, err := os.ReadFile(u)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "LoadCredential") || strings.HasPrefix(l, "SetCredential") || strings.HasPrefix(l, "ImportCredential") {
				got = append(got, l)
			}
		}
		w := want[filepath.Base(u)]
		slices.Sort(got)
		slices.Sort(w)
		if !slices.Equal(got, w) {
			t.Errorf("%s: credentials %q, want %q", filepath.Base(u), got, w)
		}
	}
}
