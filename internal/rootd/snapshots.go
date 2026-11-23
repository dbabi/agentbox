package rootd

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"agentbox/internal/ids"
	"agentbox/internal/rootd/accounts"
	"agentbox/internal/rootd/attach"
	"agentbox/internal/rootd/quota"
)

// snapSchema is Appendix E's workspace_snapshots, plus the task-start kind: rootd snapshots the workspace before every
// task's container starts, so `agentbox task undo` can put back what the task deleted (#103). Taint lives in taint.db
// as snap:<id>.
// shortcut: tree_digest stays empty until a restore approval binds one (§5.4); undo is an admin op on rootd-admin.sock.
const snapSchema = `
CREATE TABLE IF NOT EXISTS workspace_snapshots(id TEXT PRIMARY KEY, workspace TEXT NOT NULL, agent TEXT NOT NULL, task TEXT,
  kind TEXT NOT NULL CHECK(kind IN ('agent','pre-restore','clean-baseline','task-start')),
  tree_digest TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL) STRICT;
CREATE INDEX IF NOT EXISTS workspace_snapshots_ws ON workspace_snapshots(workspace, kind, id);
`

// KeepTaskStart is how many task-start snapshots each workspace keeps. Only that kind is pruned: clean-baseline,
// pre-restore and agent snapshots stay until a human removes them.
const KeepTaskStart = 5

// Btrfs is the subvolume calls snapshots make; tests replace it.
type Btrfs interface {
	// Snapshot snapshots subvolume src at dst, in qgroup q.
	Snapshot(src, dst, q string, readOnly bool) error
	Delete(subvol string) error
	// Exchange swaps two paths in one step (renameat2 RENAME_EXCHANGE).
	Exchange(a, b string) error
}

type btrfsCmd struct{}

func (btrfsCmd) Snapshot(src, dst, q string, ro bool) error {
	args := []string{"subvolume", "snapshot", "-i", q}
	if ro {
		args = append(args, "-r")
	}
	_, err := quota.Run("btrfs", append(args, src, dst)...)
	return err
}

func (btrfsCmd) Delete(p string) error {
	_, err := quota.Run("btrfs", "subvolume", "delete", p)
	return err
}

func (btrfsCmd) Exchange(a, b string) error { return exchange(a, b) }

// wsTaint is the workspace's row in auditd's view of holder, which must hold it (as a writer or a subject).
func (t *tasks) wsTaint(holder, ws string) (taintSubject, error) {
	rep, err := t.query(map[string]any{"type": "taint.get", "holder": holder})
	if err != nil || !rep.OK || rep.View == nil {
		return taintSubject{}, fmt.Errorf("auditd taint.get: %v", err)
	}
	for _, s := range rep.View.Subjects {
		if s.Subject == ws {
			return s, nil
		}
	}
	return taintSubject{}, fmt.Errorf("auditd taint.get: %s is not in %s's view", ws, holder)
}

// snapshot takes a read-only snapshot of acct's workspace into its qgroup 1/N and records it (§5.3 Snapshots carry
// taint). The INTENT binds the workspace epoch, so it is ACKed only if the taint is unchanged; snap:<id> then gets the
// taint the workspace had. holder is a task whose auditd view holds the workspace.
func (t *tasks) snapshot(acct Account, holder, task, kind string) (string, error) {
	ws := accounts.WorkspaceSubject(acct.Name, int(acct.UID))
	cur, err := t.wsTaint(holder, ws)
	if err != nil {
		return "", err
	}
	id := ids.New(ids.Snap)
	if err := t.audit(map[string]any{"type": "INTENT", "opId": id, "name": "workspace.snapshot", "origin": "rootd", "agent": acct.Name,
		"task": task, "taintEpochs": map[string]int64{ws: cur.Epoch}}); err != nil {
		return "", fmt.Errorf("audit: the snapshot INTENT was not ACKed: %v", err)
	}
	err = os.MkdirAll(acct.Snaps, 0o700)
	if err == nil {
		err = t.cfg.Btrfs.Snapshot(acct.Workspace, filepath.Join(acct.Snaps, id), quota.AgentQgroup(int(acct.UID)-accounts.UIDBase), true)
	}
	if err == nil {
		_, err = t.db.Exec(`INSERT INTO workspace_snapshots(id, workspace, agent, task, kind, created_at) VALUES(?,?,?,?,?,?)`,
			id, ws, acct.Name, task, kind, t.now())
	}
	if err == nil && cur.Tainted {
		err = t.audit(map[string]any{"type": "TAINT", "subject": "snap:" + id, "source": ws})
	}
	status, detail := "executed", ""
	if err != nil {
		status, detail = "failed", err.Error()
	}
	if aerr := t.audit(map[string]any{"type": "RESULT", "opId": id, "status": status, "detail": detail}); err == nil && aerr != nil {
		err = fmt.Errorf("audit: the snapshot RESULT was not ACKed: %v", aerr)
	}
	return id, err
}

// prune deletes the workspace's task-start snapshots past the newest KeepTaskStart. Ids sort by creation time.
func (t *tasks) prune(acct Account) {
	ws := accounts.WorkspaceSubject(acct.Name, int(acct.UID))
	rows, err := t.db.Query(`SELECT id FROM workspace_snapshots WHERE workspace=? AND kind='task-start' ORDER BY id DESC LIMIT -1 OFFSET ?`, ws, KeepTaskStart)
	if err != nil {
		log.Printf("snapshot prune %s: %v", ws, err)
		return
	}
	var old []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			old = append(old, id)
		}
	}
	rows.Close()
	for _, id := range old {
		p := filepath.Join(acct.Snaps, id)
		if err := t.cfg.Btrfs.Delete(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("snapshot prune %s: %s: %v", ws, id, err)
			continue
		}
		t.db.Exec(`DELETE FROM workspace_snapshots WHERE id=?`, id)
		log.Printf("snapshot prune %s: %s deleted", ws, id)
	}
}

// undo is `agentbox task undo <task>` on rootd-admin.sock: a signed workspace.restore of the task's start snapshot
// (§5.3). It refuses while a task or an attach of the agent is live, and holds the agent's task block throughout, so
// no task or attach starts mid-restore (a rootd crash leaves the block for `agentbox attach rescan`).
// The current tree is kept first as a pre-restore snapshot, with the current taint. auditd's INTENT sets the
// workspace taint to max(current, snapshot) as a new epoch; then the restored subvolume and the current one swap in one
// rename, and the old one is deleted.
// shortcut: the signer is the admin on rootd-admin.sock (peer uid), not an SSHSIG approval; that lands with approvals.
func (t *tasks) undo(task, signer string) reply {
	if !ids.Is(ids.Task, task) {
		return fail("bad_task_id")
	}
	var snap, agent, ws string
	err := t.db.QueryRow(`SELECT id, agent, workspace FROM workspace_snapshots WHERE task=? AND kind='task-start'`, task).Scan(&snap, &agent, &ws)
	if errors.Is(err, sql.ErrNoRows) {
		return reply{"ok": false, "error": "no start snapshot for " + task + " (pruned after " + fmt.Sprint(KeepTaskStart) + " newer tasks, or never taken)"}
	}
	if err != nil {
		return reply{"ok": false, "error": err.Error()}
	}
	acct, err := t.cfg.Accounts.Lookup(agent)
	if err != nil || accounts.WorkspaceSubject(acct.Name, int(acct.UID)) != ws {
		return reply{"ok": false, "error": "agent " + agent + " is gone or was replaced; its snapshots are archived"}
	}
	hold := "undo:" + snap
	if err := attach.Begin(t.db, agent, hold, t.cfg.Now()); err != nil {
		return reply{"ok": false, "error": "undo: " + err.Error()}
	}
	defer attach.End(t.db, agent, hold, nil)
	if n, err := t.nested(acct.Workspace); err != nil || len(n) > 0 {
		return reply{"ok": false, "error": fmt.Sprintf("undo: nested subvolumes in the workspace %q: %v", n, err)}
	}
	holder := "task:" + task
	if err := t.audit(map[string]any{"type": "SUBJECT_ADD", "task": holder, "subject": ws}); err != nil {
		return reply{"ok": false, "error": "audit: " + err.Error()}
	}
	pre, err := t.snapshot(acct, holder, task, "pre-restore")
	if err != nil {
		return reply{"ok": false, "error": "undo: pre-restore snapshot: " + err.Error()}
	}
	id := newDenyID()
	if err := t.audit(map[string]any{"type": "INTENT", "opId": id, "name": "workspace.restore", "origin": "admin", "signer": signer,
		"agent": agent, "workspace": ws, "args": map[string]string{"id": snap}}); err != nil {
		return reply{"ok": false, "error": "audit: the restore INTENT was not ACKed, nothing changed: " + err.Error()}
	}
	next := acct.Workspace + ".undo-" + snap
	err = t.cfg.Btrfs.Snapshot(filepath.Join(acct.Snaps, snap), next, quota.AgentQgroup(int(acct.UID)-accounts.UIDBase), false)
	if err == nil {
		if err = t.cfg.Btrfs.Exchange(next, acct.Workspace); err != nil {
			t.cfg.Btrfs.Delete(next)
		}
	}
	if err == nil {
		if derr := t.cfg.Btrfs.Delete(next); derr != nil { // the pre-restore snapshot holds the same tree
			log.Printf("task undo %s: the replaced workspace %s: %v", task, next, derr)
		}
	}
	status, detail := "executed", ""
	if err != nil {
		status, detail = "failed", err.Error()
	}
	aerr := t.audit(map[string]any{"type": "RESULT", "opId": id, "status": status, "detail": detail})
	if err != nil {
		return reply{"ok": false, "error": "undo: " + err.Error(), "preRestore": pre}
	}
	after, terr := t.wsTaint(holder, ws)
	log.Printf("task undo %s: workspace %s restored from %s (pre-restore %s), tainted %v", task, ws, snap, pre, after.Tainted)
	rep := reply{"ok": true, "task": task, "snapshot": snap, "preRestore": pre, "tainted": after.Tainted}
	if aerr != nil || terr != nil {
		rep["ok"], rep["error"] = false, fmt.Sprintf("restored, but the audit RESULT or taint read failed: %v %v", aerr, terr)
	}
	return rep
}
