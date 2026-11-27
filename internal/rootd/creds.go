package rootd

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"agentbox/internal/ids"
)

// The brokers' credentials (#108, ARCHITECTURE.md §4.3): secret.set encrypts each value with systemd-creds into
// CredStore/<svc>/<name>, and only that service's unit loads it, with LoadCredentialEncrypted=, into its own
// non-swappable /run/credentials dir that no other uid can read. A unit loads a credential only at start, so a new
// value restarts the unit that owns the name.
const CredStore = "/var/lib/agentbox/control/credstore.encrypted"

// Credentials are the names secret.set takes, and the service that owns each. Every broker unit's
// LoadCredentialEncrypted= lines name exactly its own (systemd/agentbox-keys.service, systemd/agentbox-git.service).
var Credentials = map[string]string{"anthropic-api-key": "keys", "openai-api-key": "keys", "github-token": "git"}

// MaxSecret is the longest value secret.set takes: vendor keys and GitHub tokens are a few hundred bytes.
const MaxSecret = 4096

// LLMUnit is the local LLM instance that keys has rootd restart on llm.recycle (§6.3).
const LLMUnit = "agentbox-llm@task.service"

// credKeyArgs is the systemd-creds key for this box: the TPM2 with an empty PCR list in the tpm2 modes, which the
// LUKS root's /etc/crypttab marks, so the credential survives kernel, firmware and generation changes on the same
// machine; the host key in none mode. The host key sits next to the root file system it encrypts for, so in none mode
// the encryption only obfuscates the stored value (docs/wiki/Security-Model.md).
func credKeyArgs(crypttab string) []string {
	b, _ := os.ReadFile(crypttab)
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			return []string{"--with-key=tpm2", "--tpm2-pcrs="}
		}
	}
	return []string{"--with-key=host"}
}

// encryptCred is systemd-creds encrypt with the value on stdin, never in argv or the environment (#108).
func encryptCred(name, value, out string) error {
	args := append([]string{"encrypt", "--name=" + name}, credKeyArgs("/etc/crypttab")...)
	cmd := exec.Command("systemd-creds", append(args, "-", out)...)
	cmd.Stdin = strings.NewReader(value)
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("systemd-creds encrypt %s: %v: %s", name, err, bytes.TrimSpace(b))
	}
	return nil
}

func (s *server) credStore() string {
	if s.cfg.CredStore != "" {
		return s.cfg.CredStore
	}
	return CredStore
}

func (s *server) encrypt(name, value, out string) error {
	if s.cfg.Encrypt != nil {
		return s.cfg.Encrypt(name, value, out)
	}
	return encryptCred(name, value, out)
}

// writeCred stores value for name: encrypted into a temp file in the service's dir, then renamed over the old one, so
// the unit never loads a half-written credential.
func (s *server) writeCred(name, value string) error {
	dir := filepath.Join(s.credStore(), Credentials[name])
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+name+".new")
	os.Remove(tmp)
	if err := s.encrypt(name, value, tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// ensureCreds gives every credential an encrypted empty value until secret.set stores one, so each broker unit's
// LoadCredentialEncrypted= finds its file and the unit starts; a broker answers a request that needs the missing
// value with its own typed denial (keys: KEYS_UPSTREAM{auth}).
func (s *server) ensureCreds() {
	for _, name := range slices.Sorted(maps.Keys(Credentials)) {
		if _, err := os.Stat(filepath.Join(s.credStore(), Credentials[name], name)); errors.Is(err, os.ErrNotExist) {
			if err := s.writeCred(name, ""); err != nil {
				log.Printf("credential %s: no placeholder: %v; agentbox-%s won't start until secret.set stores it", name, err, Credentials[name])
			}
		}
	}
}

func (s *server) restartUnit(unit string, ifRunning bool) error {
	if s.cfg.Restart != nil {
		return s.cfg.Restart(unit, ifRunning)
	}
	verb := "restart"
	if ifRunning {
		verb = "try-restart" // a stopped broker stays stopped; it loads the new value when it starts
	}
	if out, err := exec.Command("systemctl", verb, unit).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl %s %s: %v: %s", verb, unit, err, bytes.TrimSpace(out))
	}
	return nil
}

// secretSet is the admin op secret.set{name, value} (§4.3, #108): INTENT with the name only (the value is drop-class,
// so it never reaches audit), the encrypted credential, a restart of the unit that owns the name, RESULT. Nothing
// logs the value, and no reply echoes it.
func (s *server) secretSet(r request) reply {
	svc, ok := Credentials[r.Name]
	if !ok || r.Value == nil {
		return reply{"ok": false, "error": "secret.set needs a name this box knows (" + strings.Join(slices.Sorted(maps.Keys(Credentials)), ", ") + ") and a value"}
	}
	if v := *r.Value; v == "" || len(v) > MaxSecret || strings.ContainsAny(v, "\x00\r\n") {
		return reply{"ok": false, "error": fmt.Sprintf("secret.set: the value must be 1 to %d bytes on one line", MaxSecret)}
	}
	id := ids.New(ids.Op)
	if err := s.audit(map[string]any{"type": "INTENT", "opId": id, "name": "secret.set", "origin": "admin",
		"args": map[string]string{"name": r.Name}}); err != nil {
		return reply{"ok": false, "error": "audit: the INTENT was not ACKed, nothing changed: " + err.Error()}
	}
	err := s.writeCred(r.Name, *r.Value)
	restarted := false
	if err == nil {
		err = s.restartUnit("agentbox-"+svc+".service", true)
		restarted = err == nil
	}
	status, detail := "executed", ""
	if err != nil {
		status, detail = "failed", err.Error()
	}
	aerr := s.audit(map[string]any{"type": "RESULT", "opId": id, "status": status, "detail": detail, "changed": err == nil})
	if err != nil {
		return reply{"ok": false, "error": err.Error()}
	}
	log.Printf("secret.set %s: stored for agentbox-%s, which restarted", r.Name, svc)
	if aerr != nil {
		return reply{"ok": false, "error": "the secret changed, but the audit RESULT was not ACKed: " + aerr.Error()}
	}
	return reply{"ok": true, "service": "agentbox-" + svc, "restarted": restarted}
}

// llm is the llm.recycle state: keys asks for a fresh local LLM instance after a dirty one (§6.3), at most once a
// minute; a call within the minute waits for it.
type llm struct {
	mu   sync.Mutex
	last time.Time
}

func (s *server) llmRecycle() reply {
	s.llm.mu.Lock()
	defer s.llm.mu.Unlock()
	if wait := time.Until(s.llm.last.Add(time.Minute)); wait > 0 {
		time.Sleep(wait)
	}
	err := s.restartUnit(LLMUnit, false)
	s.llm.last = time.Now()
	if err != nil {
		log.Printf("llm.recycle: %v", err)
		return reply{"ok": false, "reason": "unavailable"}
	}
	log.Printf("llm.recycle: %s restarted", LLMUnit)
	return reply{"ok": true}
}

// taskTainted answers keys' task.tainted{task} (§6.3 Instance taint): the effective taint auditd holds for a live
// task. keys serves an unanswered one as tainted.
func (s *server) taskTainted(task string) reply {
	if _, ok := s.tasks.agentOf(task); !ok {
		return fail("not_live")
	}
	rep, err := s.tasks.query(map[string]any{"type": "taint.get", "holder": "task:" + task})
	if err != nil || !rep.OK || rep.View == nil {
		return fail("unavailable")
	}
	t := false
	for _, sub := range rep.View.Subjects {
		t = t || sub.Tainted
	}
	return reply{"ok": true, "tainted": t}
}
