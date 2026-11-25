package rootd

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"agentbox/internal/rootd/accounts"
	"agentbox/internal/secrets"
)

// secretSchema is each workspace's last credential scan (#104). checked means a task may start without a new scan:
// the last scan found nothing the admin had not acknowledged. A workspace with no row, or checked 0, is scanned again
// before its next task.
const secretSchema = `
CREATE TABLE IF NOT EXISTS secret_scan(workspace TEXT PRIMARY KEY, agent TEXT NOT NULL, scanned_at INTEGER NOT NULL,
  hits TEXT NOT NULL CHECK(json_valid(hits)), acked TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(acked)),
  checked INTEGER NOT NULL DEFAULT 0 CHECK(checked IN (0,1))) STRICT;
`

// Block reasons a task.start or task new gets from the credential scan.
const (
	SecretsInWorkspace = "secrets_in_workspace"
	SecretScanFailed   = "secret_scan_failed"
	SecretsAckMismatch = "secrets_ack_mismatch"
	SecretsTooMany     = "secrets_too_many"
)

// errTooManyHits is a report the scan cut off at secrets.MaxHits: files after the last hit were not read.
var errTooManyHits = fmt.Errorf("the scan stopped at %d hits", secrets.MaxHits)

// scanTimeout bounds one scan: task.start runs it within agentboxd's 60 s wait for rootd.
const scanTimeout = 45 * time.Second

// scanArgv is the transient unit the scan runs in, built like agentbox-depcheck@ (§2): a dynamic uid that can read the
// workspace (CAP_DAC_READ_SEARCH and nothing else) but not write it, no network namespace but loopback, and a root of
// only the binary and the workspace.
func scanArgv(root, exe, ws string) []string {
	argv := []string{"systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--service-type=exec"}
	for _, p := range []string{"DynamicUser=yes", "PrivateNetwork=yes", "CapabilityBoundingSet=CAP_DAC_READ_SEARCH",
		"AmbientCapabilities=CAP_DAC_READ_SEARCH", "NoNewPrivileges=yes", "RootDirectory=" + root, "MountAPIVFS=yes",
		"BindReadOnlyPaths=" + exe + ":/agentbox", "BindReadOnlyPaths=" + ws + ":/ws", "MemoryMax=1G",
		"RuntimeMaxSec=" + strconv.Itoa(int(scanTimeout.Seconds()))} {
		argv = append(argv, "-p", p)
	}
	return append(argv, "/agentbox", "secretscan", "--dir", "/ws")
}

// runSecretScan runs the scan unit on acct's workspace and checks its report against a strict schema: no unknown
// field, at most 16 MiB, loopback as its only interface, known rules and plain relative paths.
func runSecretScan(control string) func(Account) ([]secrets.Hit, error) {
	return func(acct Account) ([]secrets.Hit, error) {
		root := filepath.Join(control, "secretscan-root")
		// chmod after mkdir: rootd's UMask=0077 would leave them 0700, and the scan's uid could not enter its own root
		for _, d := range []string{"", "ws", "var", "proc", "sys", "dev", "tmp", "var/tmp"} {
			p, mode := filepath.Join(root, d), os.FileMode(0o755)
			if strings.HasSuffix(d, "tmp") {
				mode = 0o777 | os.ModeSticky
			}
			if err := os.MkdirAll(p, 0o755); err != nil {
				return nil, err
			}
			if err := os.Chmod(p, mode); err != nil {
				return nil, err
			}
		}
		if f, err := os.OpenFile(filepath.Join(root, "agentbox"), os.O_CREATE|os.O_RDONLY, 0o755); err == nil {
			f.Close()
		}
		exe, err := os.Executable()
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), scanTimeout+10*time.Second)
		defer cancel()
		argv := scanArgv(root, exe, acct.Workspace)
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		out, errb := &capped{max: 16 << 20}, &capped{max: 4096}
		cmd.Stdout, cmd.Stderr = out, errb
		t0 := time.Now()
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("the scan unit failed: %v: %s", err, bytes.TrimSpace(errb.b))
		}
		if out.over {
			return nil, errors.New("the scan report is over 16 MiB")
		}
		var rep secrets.Report
		dec := json.NewDecoder(bytes.NewReader(out.b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rep); err != nil {
			return nil, fmt.Errorf("the scan report: %v", err)
		}
		if err := checkReport(rep); err != nil {
			return nil, err
		}
		cut := ""
		if rep.Truncated {
			cut = " (cut off, files after them unread)"
		}
		log.Printf("secret scan %s: %d files, %d hits%s, in %d ms, netdevs %v", acct.Name, rep.Files, len(rep.Hits), cut, time.Since(t0).Milliseconds(), rep.Netdevs)
		if rep.Truncated {
			return rep.Hits, errTooManyHits
		}
		return rep.Hits, nil
	}
}

func checkReport(rep secrets.Report) error {
	if !slices.Equal(rep.Netdevs, []string{"lo"}) {
		return fmt.Errorf("the scan saw network interfaces %q, not only lo: report refused", rep.Netdevs)
	}
	if len(rep.Hits) > secrets.MaxHits {
		return errors.New("the scan report has too many hits")
	}
	for _, h := range rep.Hits {
		if _, ok := secrets.Lookup(h.Rule); !ok || h.Line < 1 || h.Path == "" || len(h.Path) > 4096 || path.IsAbs(h.Path) ||
			path.Clean(h.Path) != h.Path || strings.HasPrefix(h.Path, "../") || strings.ContainsFunc(h.Path, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return fmt.Errorf("the scan report has a bad hit %q", h)
		}
	}
	return nil
}

type capped struct {
	b    []byte
	max  int
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	if len(c.b)+len(p) > c.max {
		c.over = true
		p = p[:max(0, c.max-len(c.b))]
	}
	c.b = append(c.b, p...)
	return len(p), nil
}

var _ io.Writer = (*capped)(nil)

type scanState struct {
	hits, acked []secrets.Hit
	checked     bool
}

func (t *tasks) loadScan(ws string) (scanState, bool, error) {
	var h, a string
	var st scanState
	err := t.db.QueryRow(`SELECT hits, acked, checked FROM secret_scan WHERE workspace=?`, ws).Scan(&h, &a, &st.checked)
	if errors.Is(err, sql.ErrNoRows) {
		return st, false, nil
	}
	if err == nil {
		err = errors.Join(json.Unmarshal([]byte(h), &st.hits), json.Unmarshal([]byte(a), &st.acked))
	}
	return st, err == nil, err
}

func (t *tasks) saveScan(acct Account, st scanState) error {
	h, _ := json.Marshal(append([]secrets.Hit{}, st.hits...))
	a, _ := json.Marshal(append([]secrets.Hit{}, st.acked...))
	_, err := t.db.Exec(`INSERT INTO secret_scan(workspace, agent, scanned_at, hits, acked, checked) VALUES(?,?,?,?,?,?)
		ON CONFLICT(workspace) DO UPDATE SET scanned_at=excluded.scanned_at, hits=excluded.hits, acked=excluded.acked, checked=excluded.checked`,
		accounts.WorkspaceSubject(acct.Name, int(acct.UID)), acct.Name, t.now(), string(h), string(a), st.checked)
	return err
}

// covered: every hit is one the admin acknowledged.
func covered(hits, acked []secrets.Hit) bool {
	for _, h := range hits {
		if !slices.Contains(acked, h) {
			return false
		}
	}
	return true
}

// rescan scans acct's workspace and records it. A scan never marks the workspace checked unless every hit is
// acknowledged, so new hits block the next task; firstTask false (workspace creation, an egress grant) leaves it
// unchecked, since only the scan right before a task counts for that task. A truncated scan never does, and no ack
// covers it: the files it did not read may hold more. The workspace is unchecked from before the scan until a result
// is saved, so a scan that fails, or a rootd that stops mid-scan, leaves the next task to scan again (#208). One scan
// of a workspace runs at a time, so an older one can't save over a newer one's hits (#224).
func (t *tasks) rescan(acct Account, ack int, firstTask bool) ([]secrets.Hit, reply) {
	ws := accounts.WorkspaceSubject(acct.Name, int(acct.UID))
	v, _ := t.scans.LoadOrStore(ws, &sync.Mutex{})
	v.(*sync.Mutex).Lock()
	defer v.(*sync.Mutex).Unlock()
	if _, err := t.db.Exec(`UPDATE secret_scan SET checked=0 WHERE workspace=?`, ws); err != nil {
		return nil, reply{"ok": false, "reason": SecretScanFailed, "error": err.Error()}
	}
	hits, err := t.cfg.SecretScan(acct)
	capped := errors.Is(err, errTooManyHits)
	if err != nil && !capped {
		log.Printf("secret scan %s: %v", acct.Name, err)
		return nil, reply{"ok": false, "reason": SecretScanFailed, "error": "the workspace credential scan failed, so tasks stay blocked: " + err.Error()}
	}
	st, _, err := t.loadScan(ws)
	if err != nil {
		return nil, reply{"ok": false, "reason": SecretScanFailed, "error": err.Error()}
	}
	if ack > 0 && !capped {
		if ack != len(hits) {
			return hits, reply{"ok": false, "reason": SecretsAckMismatch, "secrets": hits,
				"error": fmt.Sprintf("--ack-secrets %d, but the scan found %d: %s", ack, len(hits), list(hits))}
		}
		st.acked = hits
	}
	st.hits = hits
	st.checked = firstTask && !capped && covered(hits, st.acked)
	if err := t.saveScan(acct, st); err != nil {
		return nil, reply{"ok": false, "reason": SecretScanFailed, "error": err.Error()}
	}
	if capped {
		return hits, reply{"ok": false, "reason": SecretsTooMany, "secrets": hits,
			"error": fmt.Sprintf("the workspace credential scan stopped at %d hits, so it did not read every file and tasks stay blocked; "+
				"--ack-secrets can't acknowledge a partial list: remove credentials until the scan finds fewer: %s", secrets.MaxHits, list(hits))}
	}
	if !covered(hits, st.acked) {
		return hits, reply{"ok": false, "reason": SecretsInWorkspace, "secrets": hits,
			"error": fmt.Sprintf("the workspace holds %d credential(s) a task could use against an allowed host: %s; remove them, "+
				"or acknowledge with agentbox task new --ack-secrets %d", len(hits), list(hits), len(hits))}
	}
	return hits, nil
}

func list(hits []secrets.Hit) string {
	var s []string
	for i, h := range hits {
		if i == 20 {
			s = append(s, fmt.Sprintf("and %d more", len(hits)-i))
			break
		}
		s = append(s, h.String())
	}
	return strings.Join(s, ", ")
}

// secretGate is the check before a task (#104): a workspace that passed its last scan, with every hit acknowledged,
// starts at once; any other is scanned first. ack > 0 is the admin's --ack-secrets: it must equal the hit count.
func (t *tasks) secretGate(acct Account, ack int) reply {
	if t.cfg.SecretScan == nil {
		return nil
	}
	if st, ok, err := t.loadScan(accounts.WorkspaceSubject(acct.Name, int(acct.UID))); err == nil && ok && st.checked && ack == 0 {
		return nil
	}
	_, rep := t.rescan(acct, ack, true)
	return rep
}

// grantScan is the scan at an egress grant for host: every active agent's workspace is scanned again, and the reply
// names each credential that works against host. Each one blocks that agent's next task until it is acknowledged
// (again, if it was before the grant) or removed.
func (t *tasks) grantScan(agents []string, host string) (matching []map[string]any, failed []string) {
	if t.cfg.SecretScan == nil {
		return nil, nil
	}
	for _, name := range agents {
		acct, err := t.cfg.Accounts.Lookup(name)
		if err != nil {
			continue
		}
		hits, rep := t.rescan(acct, 0, false)
		if rep != nil && (rep["reason"] == SecretScanFailed || rep["reason"] == SecretsTooMany) {
			failed = append(failed, name)
		}
		for _, h := range hits {
			if secrets.ForHost(h.Rule, host) {
				matching = append(matching, map[string]any{"agent": name, "path": h.Path, "line": h.Line, "type": h.Rule})
			}
		}
		if err := t.dropAcks(acct, host); err != nil {
			log.Printf("secret scan %s: acks for %s: %v", name, host, err)
			if !slices.Contains(failed, name) {
				failed = append(failed, name)
			}
		}
	}
	return matching, failed
}

// dropAcks forgets every acknowledged hit that works against host. The admin acked it while host was not allowed, so
// with host allowed it blocks the agent's next task until an --ack-secrets again.
func (t *tasks) dropAcks(acct Account, host string) error {
	st, ok, err := t.loadScan(accounts.WorkspaceSubject(acct.Name, int(acct.UID)))
	if err != nil || !ok {
		return err
	}
	n := len(st.acked)
	st.acked = slices.DeleteFunc(st.acked, func(h secrets.Hit) bool { return secrets.ForHost(h.Rule, host) })
	if len(st.acked) == n {
		return nil
	}
	st.checked = false
	return t.saveScan(acct, st)
}

func (s *server) activeAgents() []string {
	all, err := accounts.List(s.db)
	if err != nil {
		log.Printf("secret scan: agents: %v", err)
	}
	var out []string
	for _, a := range all {
		if a.Active {
			out = append(out, a.Name)
		}
	}
	return out
}

// grantWarning is the line the admin reads at the grant: each credential, by type and file, that the grant lets a
// task use.
func grantWarning(found []map[string]any, host string) string {
	var s []string
	for _, f := range found {
		s = append(s, fmt.Sprintf("a %s in %s's workspace (%s:%d)", f["type"], f["agent"], f["path"], f["line"]))
	}
	return "with " + host + " allowed, a task can use " + strings.Join(s, ", ") + "; that agent's tasks are blocked until it is removed or acknowledged (--ack-secrets)"
}
