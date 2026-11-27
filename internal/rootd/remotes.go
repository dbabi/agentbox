package rootd

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"time"

	"agentbox/internal/git"
	"agentbox/internal/ids"
	"agentbox/internal/ops"
	"agentbox/internal/rootd/accounts"
)

// gitSchema is rootd.db's part of the git ops (Appendix E): remotes, which only the admin op remote.set writes;
// pending and used_nonces, the stored P that each remote write and merge waits in for a human (§5.2); and
// task_canaries, each live task's canary (#105).
const gitSchema = `
CREATE TABLE IF NOT EXISTS remotes(id TEXT PRIMARY KEY, project TEXT NOT NULL, owner TEXT NOT NULL, remote_url TEXT NOT NULL, gh_node_id TEXT NOT NULL,
                     visibility TEXT NOT NULL CHECK(visibility IN ('private','internal','public')), created_at INTEGER) STRICT;
CREATE TABLE IF NOT EXISTS pending(id TEXT PRIMARY KEY, task TEXT NOT NULL, agent TEXT NOT NULL, op TEXT NOT NULL CHECK(json_valid(op)),
                     bound TEXT NOT NULL CHECK(json_valid(bound)), h TEXT UNIQUE NOT NULL, nonce TEXT UNIQUE NOT NULL,
                     state TEXT NOT NULL CHECK(state IN ('pending','approved','executing','executed','refused','failed','indeterminate','denied','expired')),
                     signer TEXT, reason TEXT, result TEXT CHECK(result IS NULL OR json_valid(result)), match_key TEXT NOT NULL,
                     batch TEXT, batch_idx INTEGER, expires_at INTEGER NOT NULL, approved_at INTEGER, created_at INTEGER NOT NULL,
                     CHECK(expires_at > created_at), CHECK((batch IS NULL) = (batch_idx IS NULL))) STRICT;
CREATE INDEX IF NOT EXISTS pending_task ON pending(task, state);
CREATE INDEX IF NOT EXISTS pending_match ON pending(task, match_key);
CREATE INDEX IF NOT EXISTS pending_batch ON pending(batch, batch_idx) WHERE batch IS NOT NULL;
CREATE TABLE IF NOT EXISTS used_nonces(nonce TEXT PRIMARY KEY, used_at INTEGER NOT NULL) STRICT;
CREATE TABLE IF NOT EXISTS task_canaries(task TEXT PRIMARY KEY, canary TEXT NOT NULL) STRICT;
`

// GitCall sends one call to agentbox-git's svc-git.sock and returns the reply; ErrNoSvc if the service isn't installed.
type GitCall func(req map[string]any, timeout time.Duration) (map[string]any, error)

// gitCall is the box's: svc-git.sock, with the caller's timeout (a push or a reconcile listing can take minutes).
func gitCall(req map[string]any, timeout time.Duration) (map[string]any, error) {
	return svcCallFor("git", req, timeout)
}

// reRemoteID is a remotes row id: the ops grammar for a remote, so a denial can name it.
var reRemoteID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

type remoteRow struct {
	ID         string `json:"id"`
	Project    string `json:"project"`
	Owner      string `json:"owner"`
	URL        string `json:"remote_url"`
	NodeID     string `json:"gh_node_id"`
	Visibility string `json:"visibility"`
}

// remote is the remotes row id that owner owns. Another agent's row and a missing one are one miss (§5.2).
func (s *server) remote(id, owner string) (remoteRow, bool) {
	var r remoteRow
	if !reRemoteID.MatchString(id) {
		return r, false
	}
	err := s.db.QueryRow(`SELECT id, project, owner, remote_url, gh_node_id, visibility FROM remotes WHERE id=? AND owner=?`, id, owner).
		Scan(&r.ID, &r.Project, &r.Owner, &r.URL, &r.NodeID, &r.Visibility)
	return r, err == nil
}

// gitOK calls the git service and returns its reply if it says ok; otherwise an error with the service's reason.
func (s *server) gitOK(req map[string]any, timeout time.Duration) (map[string]any, error) {
	rep, err := s.git(req, timeout)
	if err != nil {
		return nil, fmt.Errorf("agentbox-git: %w", err)
	}
	if rep["ok"] != true {
		return rep, fmt.Errorf("agentbox-git: %v %v %v", rep["error"], rep["what"], rep["detail"])
	}
	return rep, nil
}

// remoteSet is the admin op remote.set{id, agent, project, url} (Appendix E remotes): GitHub REST gives the repo's
// node id and visibility, the agent's local repo project is made if missing, and the row is written (or replaced)
// between INTENT and RESULT.
func (s *server) remoteSet(r request) reply {
	o, _ := ops.Lookup("remote.set")
	args, aerr := o.ValidateArgs(r.Args)
	if aerr != nil {
		return reply{"ok": false, "error": "remote.set: " + aerr.Error()}
	}
	id, agent, project, url := args["id"].(string), args["agent"].(string), args["project"].(string), args["url"].(string)
	owner, repo, err := git.ParseRemoteURL(url)
	switch {
	case err != nil:
		return reply{"ok": false, "error": "remote.set: " + err.Error()}
	case !reRemoteID.MatchString(id):
		return reply{"ok": false, "error": "remote.set: an id is [a-z0-9][a-z0-9._-], at most 64 bytes"}
	case !git.ValidProject(project):
		return reply{"ok": false, "error": "remote.set: a project is [a-z0-9][a-z0-9_-], at most 64 bytes"}
	}
	if a, err := accounts.Lookup(s.db, agent); err != nil || !a.Active {
		return reply{"ok": false, "error": "remote.set: no active agent " + agent}
	}
	var other string
	if err := s.db.QueryRow(`SELECT owner FROM remotes WHERE id=?`, id).Scan(&other); err == nil && other != agent {
		return reply{"ok": false, "error": "remote.set: remote id " + id + " belongs to another agent; pick another id"}
	}
	url = git.CanonURL(owner, repo)
	rep, err := s.gitOK(map[string]any{"call": "remote.lookup", "url": url}, 2*time.Minute)
	if err != nil {
		return reply{"ok": false, "error": "remote.set: GitHub did not answer for " + url + ": " + err.Error()}
	}
	node, _ := rep["nodeId"].(string)
	vis, _ := rep["visibility"].(string)
	opID := ids.New(ids.Op)
	in := map[string]any{"id": id, "agent": agent, "project": project, "url": url}
	if err := s.audit(map[string]any{"type": "INTENT", "opId": opID, "name": "remote.set", "origin": "admin", "args": ops.Classify(o.Args, in),
		"ts": time.Now().UnixMilli()}); err != nil {
		return reply{"ok": false, "error": "audit: the INTENT was not ACKed, nothing changed: " + err.Error()}
	}
	err = nil
	if _, cerr := s.gitOK(map[string]any{"call": "repo.create", "agent": agent, "project": project}, time.Minute); cerr != nil {
		err = cerr
	} else {
		_, err = s.db.Exec(`INSERT INTO remotes(id, project, owner, remote_url, gh_node_id, visibility, created_at) VALUES(?,?,?,?,?,?,?)
			ON CONFLICT(id) DO UPDATE SET project=excluded.project, remote_url=excluded.remote_url, gh_node_id=excluded.gh_node_id,
			visibility=excluded.visibility`, id, project, agent, url, node, vis, time.Now().UnixMilli())
	}
	res := map[string]any{"type": "RESULT", "opId": opID, "status": "executed", "outputs": map[string]any{"nodeId": node, "visibility": vis}}
	if err != nil {
		res = map[string]any{"type": "RESULT", "opId": opID, "status": "failed", "detail": trunc(err.Error(), 1024)}
	}
	if aerr := s.audit(res); aerr != nil {
		log.Printf("remote.set %s: RESULT not audited: %v", id, aerr)
	}
	if err != nil {
		return reply{"ok": false, "error": "remote.set: " + err.Error()}
	}
	log.Printf("remote.set %s: agent %s, project %s, %s (%s)", id, agent, project, url, vis)
	return reply{"ok": true, "remote": remoteRow{id, project, agent, url, node, vis}}
}

// remoteList is `agentbox remote list` (admin): every row, or one agent's.
func (s *server) remoteList(agent string) reply {
	rows, err := s.db.Query(`SELECT id, project, owner, remote_url, gh_node_id, visibility FROM remotes WHERE ?='' OR owner=? ORDER BY owner, id`, agent, agent)
	if err != nil {
		return reply{"ok": false, "error": err.Error()}
	}
	defer rows.Close()
	out := []remoteRow{}
	for rows.Next() {
		var r remoteRow
		if err := rows.Scan(&r.ID, &r.Project, &r.Owner, &r.URL, &r.NodeID, &r.Visibility); err != nil {
			return reply{"ok": false, "error": err.Error()}
		}
		out = append(out, r)
	}
	return reply{"ok": true, "remotes": out}
}

// canaryOf is task's canary, or "" if it has none (#105).
func (s *server) canaryOf(task string) string {
	var c string
	s.db.QueryRow(`SELECT canary FROM task_canaries WHERE task=?`, task).Scan(&c)
	return c
}

// taskAgent is the task_registry row of task: its agent, and whether it is live (ended_at IS NULL) or ended
// completed, the two states a pending op may still execute in (§5.2 re-check).
func (s *server) taskAgent(task string) (agent string, live, completed bool, err error) {
	var ended sql.NullInt64
	var why sql.NullString
	err = s.db.QueryRow(`SELECT agent, ended_at, end_reason FROM task_registry WHERE task=?`, task).Scan(&agent, &ended, &why)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, false, nil
	}
	return agent, err == nil && !ended.Valid, why.String == "completed", err
}

// effectiveTaint is the task's effective taint (§5.2) from auditd: whether any subject of its set is tainted, and
// the {subject: epoch} map that the op's INTENT binds.
func (s *server) effectiveTaint(task string) (bool, map[string]int64, error) {
	if s.tasks == nil || s.tasks.query == nil {
		return true, map[string]int64{}, errors.New("no auditd query")
	}
	rep, err := s.tasks.query(map[string]any{"type": "taint.get", "holder": "task:" + task})
	if err != nil {
		return true, nil, err
	}
	if !rep.OK || rep.View == nil {
		return true, nil, errors.New("auditd refused taint.get")
	}
	tainted, epochs := false, map[string]int64{}
	for _, x := range rep.View.Subjects {
		tainted = tainted || x.Tainted
		epochs[x.Subject] = x.Epoch
	}
	return tainted, epochs, nil
}

// canonJSON is v as JSON with every object's keys sorted, numbers as written and no HTML escaping: the bytes H and
// the match key hash.
// shortcut: Go's canonical JSON, not RFC 8785 JCS; the laptop recomputes H with JCS once SSHSIG approvals land (#24).
func canonJSON(v any) []byte {
	b, _ := json.Marshal(v)
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var x any
	d.Decode(&x) // a map: Encode sorts its keys
	var out bytes.Buffer
	e := json.NewEncoder(&out)
	e.SetEscapeHTML(false)
	e.Encode(x)
	return bytes.TrimSuffix(out.Bytes(), []byte("\n"))
}
