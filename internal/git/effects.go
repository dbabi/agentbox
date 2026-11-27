package git

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"agentbox/internal/ids"
)

// Bound is what rootd bound into an op's P (§5.2) and sends with exec and reconcile: the remotes row's URL and node
// id, the local project, and the op's own OIDs, refs and numbers. The service acts on these, never on a resubmitted
// request.
type Bound struct {
	Remote     string `json:"remote,omitempty"` // the remotes row id
	URL        string `json:"remoteUrl,omitempty"`
	NodeID     string `json:"ghNodeId,omitempty"`
	Visibility string `json:"visibility,omitempty"`
	Project    string `json:"project"`
	OID        string `json:"oid,omitempty"` // repo.push: the commit pushed; gh.pr.create: the head commit
	Ref        string `json:"ref,omitempty"` // repo.push: the remote ref; gh.pr.create: the head ref
	Base       string `json:"base,omitempty"`
	Number     int64  `json:"number,omitempty"`
	Marker     string `json:"marker,omitempty"` // gh.*: the id in the body's op marker
	BodyHash   string `json:"bodySha256,omitempty"`
	SrcOID     string `json:"srcOid,omitempty"` // repo.merge
	DstOID     string `json:"dstOid,omitempty"` // repo.merge: main's commit at bind, "" when main doesn't exist yet
}

// opArgs are the op args an effect needs.
type opArgs struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

// errStale is an effect whose bound state moved (STALE{ref_moved}).
var errStale = errors.New("ref_moved")

// exec runs one approved op's effect, once: rootd has the INTENT ACKed and sends the stored P's args and bound inputs.
func (s *Server) exec(r ctlReq) map[string]any {
	var b Bound
	var a opArgs
	if !ids.Is(ids.Pending, r.ID) || json.Unmarshal(r.Bound, &b) != nil || len(r.Args) > 0 && json.Unmarshal(r.Args, &a) != nil ||
		!reAgent.MatchString(r.Agent) || !ValidProject(b.Project) {
		return bad(errors.New("bad exec request"))
	}
	if err := startOp(s.store, r.ID, r.Name, s.Now().UnixMilli()); err != nil {
		return bad(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	repo := Repo(s.Root, r.Agent, b.Project)
	switch r.Name {
	case "repo.push":
		if err := s.Pusher.Push(ctx, repo, b.URL, b.OID, b.Ref); err != nil {
			return refused(err)
		}
		return ok("outputs", map[string]any{"remote": b.Remote, "oid": b.OID})
	case "gh.pr.create":
		owner, name, err := ParseRemoteURL(b.URL)
		if err != nil {
			return bad(err)
		}
		it, err := s.GitHub.CreatePR(ctx, owner, name, a.Title, strings.TrimPrefix(b.Ref, "refs/heads/"), b.Base, a.Body)
		if err != nil {
			return refused(err)
		}
		return ok("outputs", map[string]any{"remote": b.Remote, "headOid": b.OID, "number": it.Number, "url": it.URL})
	case "gh.pr.comment", "gh.issue.comment":
		owner, name, err := ParseRemoteURL(b.URL)
		if err != nil {
			return bad(err)
		}
		it, err := s.GitHub.Comment(ctx, owner, name, b.Number, a.Body)
		if err != nil {
			return refused(err)
		}
		return ok("outputs", map[string]any{"remote": b.Remote, "id": it.ID, "url": it.URL})
	case "repo.merge":
		oid, tainted, err := s.merge(r.Task, r.Agent, b, r.ID)
		if errors.Is(err, errStale) {
			return map[string]any{"ok": false, "stale": "ref_moved"}
		}
		if err != nil {
			return map[string]any{"ok": false, "failed": true, "detail": err.Error()}
		}
		return ok("outputs", map[string]any{"oid": oid, "tainted": tainted})
	}
	return bad(fmt.Errorf("no effect for %q", r.Name))
}

// srcTainted is taint(src at srcOid) (§6.3 Merge taint): a commit that merging brings into main was recorded as
// tainted by pre-receive, or src is the tip of a ref a tainted push or merge updated.
func (s *Server) srcTainted(agent string, b Bound) (bool, error) {
	repo := Repo(s.Root, agent, b.Project)
	name := RepoName(agent, b.Project)
	in, err := Between(repo, b.SrcOID, b.DstOID)
	if err != nil {
		return false, err
	}
	if t, err := anyTaintedCommit(s.store, name, in); err != nil || t {
		return t, err
	}
	refs, err := taintedRefs(s.store, name)
	if err != nil {
		return false, err
	}
	tips, err := Tips(repo)
	if err != nil {
		return false, err
	}
	for _, r := range refs {
		if tips[r] == b.SrcOID {
			return true, nil
		}
	}
	return false, nil
}

// merge is repo.merge's effect (§5.3, §6.3): compare-and-swap of main from dstOid to the merge of srcOid. Merge taint
// comes first: taint(main) |= taint(src at srcOid), ACKed by auditd before main moves, so no fetch sees the merged
// main untainted. A merge signature doesn't clear taint.
func (s *Server) merge(task, agent string, b Bound, id string) (string, bool, error) {
	repo := Repo(s.Root, agent, b.Project)
	main, err := Tip(repo, "refs/heads/main")
	if err != nil {
		return "", false, err
	}
	if main != b.DstOID {
		return "", false, errStale
	}
	if ok, err := Contains(repo, b.SrcOID); err != nil || !ok {
		return "", false, fmt.Errorf("source %s is in no branch: %v", b.SrcOID, err)
	}
	tainted, err := s.srcTainted(agent, b)
	if err != nil {
		return "", false, err
	}
	msg := "Merge " + b.SrcOID + " into main\n\nagentbox repo.merge " + id + "\n"
	commit, err := MergeCommit(repo, b.SrcOID, b.DstOID, msg, s.Now())
	if err != nil {
		return "", false, err
	}
	if tainted {
		if err := s.Audit.Send(map[string]any{"type": "TAINT", "subject": RefSubject(agent, b.Project, "refs/heads/main"),
			"source": "merge:" + b.SrcOID}); err != nil {
			return "", false, fmt.Errorf("auditd TAINT: %v", err)
		}
		if err := markTainted(s.store, RepoName(agent, b.Project), task, []string{"refs/heads/main"}, nil, s.Now().UnixMilli()); err != nil {
			return "", false, err
		}
	}
	if err := MoveRef(repo, "refs/heads/main", commit, b.DstOID); err != nil {
		return "", false, errStale
	}
	return commit, tainted, nil
}

// reconcile finds an effect whose INTENT has no RESULT, after a rootd restart (§5.2 recovery, §5.3), and never runs
// it again: repo.push compares the remote ref with the bound OID; gh.* lists candidates and matches the token user's
// item that ends with the op marker; repo.merge checks main.
func (s *Server) reconcile(r ctlReq) map[string]any {
	var b Bound
	if json.Unmarshal(r.Bound, &b) != nil || !reAgent.MatchString(r.Agent) || !ValidProject(b.Project) {
		return bad(errors.New("bad reconcile request"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	repo := Repo(s.Root, r.Agent, b.Project)
	switch r.Name {
	case "repo.push":
		oid, err := s.Pusher.RemoteRef(ctx, repo, b.URL, b.Ref)
		if err != nil {
			return refused(err)
		}
		if oid != b.OID {
			return ok("found", false)
		}
		return ok("found", true, "outputs", map[string]any{"remote": b.Remote, "oid": b.OID})
	case "gh.pr.create", "gh.pr.comment", "gh.issue.comment":
		owner, name, err := ParseRemoteURL(b.URL)
		if err != nil {
			return bad(err)
		}
		var it Item
		var found bool
		if r.Name == "gh.pr.create" {
			it, found, err = s.GitHub.FindPR(ctx, owner, name, strings.TrimPrefix(b.Ref, "refs/heads/"), b.Base, b.Marker)
		} else {
			it, found, err = s.GitHub.FindComment(ctx, owner, name, b.Number, time.UnixMilli(r.Since).Add(-time.Minute), b.Marker)
		}
		if err != nil {
			return refused(err)
		}
		if !found {
			return ok("found", false)
		}
		if r.Name == "gh.pr.create" {
			return ok("found", true, "outputs", map[string]any{"remote": b.Remote, "headOid": b.OID, "number": it.Number, "url": it.URL})
		}
		return ok("found", true, "outputs", map[string]any{"remote": b.Remote, "id": it.ID, "url": it.URL})
	case "repo.merge":
		oid, done, err := Merged(repo, b.SrcOID, b.DstOID)
		if err != nil {
			return bad(err)
		}
		if !done {
			return ok("found", false)
		}
		t, _ := s.srcTainted(r.Agent, b)
		return ok("found", true, "outputs", map[string]any{"oid": oid, "tainted": t})
	}
	return bad(fmt.Errorf("no reconcile for %q", r.Name))
}

// remoteRef answers remote.ref for rootd's execution re-check: ref's commit on the remote.
func (s *Server) remoteRef(r ctlReq) map[string]any {
	if !reAgent.MatchString(r.Agent) || !ValidProject(r.Project) {
		return bad(errors.New("bad remote.ref request"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	oid, err := s.Pusher.RemoteRef(ctx, Repo(s.Root, r.Agent, r.Project), r.URL, r.Ref)
	if err != nil {
		return refused(err)
	}
	return ok("oid", oid)
}
