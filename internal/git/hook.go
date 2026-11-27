package git

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"agentbox/internal/canary"
	"agentbox/internal/ops"
	"agentbox/internal/secrets"
)

// HookEnv names the request file the service writes for each push.
const HookEnv = "AGENTBOX_GIT_HOOK"

// HookRequest is what the hook acts on, written by the service for one push (0600, in its own temp dir): the hook
// takes nothing from the pusher but git's ref updates and the pushed objects.
type HookRequest struct {
	Task    string `json:"task"`
	Agent   string `json:"agent"`
	Project string `json:"project"`
	Canary  string `json:"canary,omitempty"`
	DayCap  int64  `json:"dayCap"`
	Store   string `json:"store"`   // git/, which holds .state.db
	Resolve string `json:"resolve"` // rootd's resolve-git.sock
	Audit   string `json:"audit"`   // auditd's git.sock
}

// RefUpdate is one line of pre-receive's stdin: a ref's old and new OIDs.
type RefUpdate struct{ Old, New, Ref string }

// maxRefUpdates bounds one push: a push of more refs than this is refused, not read without end.
const maxRefUpdates = 4096

// ParseRefUpdates reads pre-receive's stdin ("<old> <new> <ref>" lines). A line the hook can't parse fails the push.
func ParseRefUpdates(r io.Reader) ([]RefUpdate, error) {
	var out []RefUpdate
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 3 || !ValidOID(f[0]) || !ValidOID(f[1]) || len(out) == maxRefUpdates {
			return nil, fmt.Errorf("bad pre-receive line %q", sc.Text())
		}
		out = append(out, RefUpdate{f[0], f[1], f[2]})
	}
	return out, sc.Err()
}

func zero(oid string) bool { return strings.Trim(oid, "0") == "" }

// DirSize sums the regular-file bytes under dir: the push's quarantine (GIT_QUARANTINE_PATH). No dir is 0.
func DirSize(dir string) (int64, error) {
	if dir == "" {
		return 0, nil
	}
	var n int64
	err := filepath.WalkDir(dir, func(_ string, e fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if e.Type().IsRegular() {
			fi, err := e.Info()
			if err != nil {
				return err
			}
			n += fi.Size()
		}
		return nil
	})
	return n, err
}

// pushScan is what a push brings in: its new commits, whether any object holds the canary, and the gitleaks rules
// that matched a new file.
type pushScan struct {
	Commits []string
	Canary  bool
	Secrets []string
}

// scanPush lists the objects the push brings in that no ref has yet (`rev-list --objects ... --not --all`) and reads
// each one through `cat-file --batch`, in pieces, so a large blob costs bounded memory. env is the hook's own: it
// names the quarantine, where the pushed objects are until the hook accepts them. One canary scanner reads them
// all, so a value split across two files that git sends next to each other is found too.
func scanPush(repo string, env, news []string, c string, extra []byte) (pushScan, error) {
	var res pushScan
	sc := canary.New(c)
	if sc != nil {
		sc.Write(extra)
	}
	if len(news) == 0 {
		res.Canary = sc.Hit()
		return res, nil
	}
	var stderr strings.Builder
	rl := exec.Command("git", append(append([]string{"-C", repo, "rev-list", "--objects", "--no-object-names"}, news...), "--not", "--all")...)
	rl.Env, rl.Stderr = env, &stderr
	out, err := rl.Output()
	if err != nil {
		return res, fmt.Errorf("rev-list: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	objs := strings.Fields(string(out))
	if len(objs) == 0 {
		res.Canary = sc.Hit()
		return res, nil
	}
	cmd := exec.Command("git", "-C", repo, "cat-file", "--batch")
	cmd.Env = env
	in, err := cmd.StdinPipe()
	if err != nil {
		return res, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return res, err
	}
	if err := cmd.Start(); err != nil {
		return res, err
	}
	go func() {
		w := bufio.NewWriter(in)
		for _, o := range objs {
			w.WriteString(o + "\n")
		}
		w.Flush()
		in.Close()
	}()
	br := bufio.NewReaderSize(stdout, 64<<10)
	found := map[string]bool{}
	buf := make([]byte, 1<<20)
	var serr error
	for range objs {
		line, err := br.ReadString('\n')
		if err != nil {
			serr = err
			break
		}
		f := strings.Fields(line)
		if len(f) != 3 {
			serr = fmt.Errorf("cat-file: %q", line)
			break
		}
		size, err := strconv.ParseInt(f[2], 10, 64)
		if err != nil || size < 0 {
			serr = fmt.Errorf("cat-file: %q", line)
			break
		}
		if f[1] == "commit" {
			res.Commits = append(res.Commits, f[0])
		}
		var keep []byte // a blob's first secrets.FileCap bytes, for the gitleaks rules
		for left := size; left > 0; {
			n, err := io.ReadFull(br, buf[:min(left, int64(len(buf)))])
			if err != nil {
				serr = err
				break
			}
			left -= int64(n)
			if sc != nil {
				sc.Write(buf[:n])
			}
			if f[1] == "blob" && len(keep) < secrets.FileCap {
				keep = append(keep, buf[:min(n, secrets.FileCap-len(keep))]...)
			}
		}
		if serr != nil {
			break
		}
		if _, err := br.Discard(1); err != nil { // the LF after each object
			serr = err
			break
		}
		for _, h := range secrets.Find(f[0], keep) {
			found[h.Rule] = true
		}
	}
	io.Copy(io.Discard, br)
	werr := cmd.Wait()
	if serr != nil {
		return res, serr
	}
	if werr != nil {
		return res, werr
	}
	for r := range found {
		res.Secrets = append(res.Secrets, r)
	}
	slices.Sort(res.Secrets)
	res.Canary = sc.Hit()
	return res, nil
}

// capDenial is the daily cap's CAP_REACHED{push_bytes_day}: the cap, and when it resets (the next 00:00 UTC).
func capDenial(limit int64, now time.Time) ops.Denial {
	reset := DayStart(now) + 24*time.Hour.Milliseconds()
	return ops.Deny(ops.CapReached, "push_bytes_day", ops.Slots{Op: "repo.push", By: "git", Limit: &limit, ResetsAt: &reset})
}

// Hook is `agentbox git-hook pre-receive`, the root-owned hook of every local push (§6.3). It refuses a ref outside
// refs/heads/agent/<name>/ (REF_OUTSIDE_NAMESPACE), a push over the agent's daily cap, measured from the
// quarantine before git stores a byte (CAP_REACHED{push_bytes_day}), and a push whose objects or ref names hold the
// task's canary (EXFIL_CANARY: rootd taints the task and alerts). Then rootd says whether the task is tainted: if
// so, it has tainted the refs, and the hook records them and the new commits as tainted. A refusal prints the two
// §5.6 lines, which git shows as remote: lines, and exits 1, so git keeps none of the push. Anything the hook can't
// check refuses too.
func Hook(stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string, now time.Time) int {
	fail := func(msg string) int {
		fmt.Fprintln(stderr, "agentbox: pre-receive: "+msg)
		return 1
	}
	var req HookRequest
	b, err := os.ReadFile(getenv(HookEnv))
	if err != nil || json.Unmarshal(b, &req) != nil || !reAgent.MatchString(req.Agent) || !ValidProject(req.Project) || req.DayCap <= 0 {
		return fail("no push request from agentbox-git")
	}
	aud := Auditor{req.Audit}
	refuse := func(d ops.Denial, detail string) int {
		aud.Deny(d, req.Task, req.Agent, detail)
		stdout.Write(ops.GitBody(d))
		return 1
	}
	ups, err := ParseRefUpdates(stdin)
	if err != nil {
		return fail("its ref updates do not parse")
	}
	var news, refs []string
	var names strings.Builder
	for _, u := range ups {
		if !InNamespace(req.Agent, u.Ref) {
			return refuse(ops.Deny(ops.RefOutsideNamespace, "", ops.Slots{Op: "repo.push", By: "git", Subject: ops.Subject{Ref: u.Ref},
				Expect: "refs/heads/agent/<name>/*"}), "")
		}
		names.WriteString(u.Ref + "\n")
		if !zero(u.New) {
			news, refs = append(news, u.New), append(refs, u.Ref)
		}
	}
	size, err := DirSize(getenv("GIT_QUARANTINE_PATH"))
	if err != nil {
		return fail("the push can't be sized")
	}
	db, err := OpenStore(req.Store)
	if err != nil {
		return fail("no state store")
	}
	defer db.Close()
	used, err := usedToday(db, req.Agent, now)
	if err != nil {
		return fail("no day total")
	}
	if used+size > req.DayCap {
		return refuse(capDenial(req.DayCap, now), fmt.Sprintf("push of %d bytes, %d used today", size, used))
	}
	repo, err := os.Getwd()
	if err != nil {
		return fail("no repo")
	}
	scan, err := scanPush(repo, os.Environ(), news, req.Canary, []byte(names.String()))
	if err != nil {
		return fail("the pushed objects can't be read: " + err.Error())
	}
	rd := Rootd{req.Resolve}
	if scan.Canary {
		if _, err := rd.Call(map[string]any{"op": "canary.hit", "task": req.Task, "name": "repo.push"}, 30*time.Second); err != nil {
			fmt.Fprintln(stderr, "agentbox: pre-receive: rootd did not record the canary hit:", err)
		}
		return refuse(ops.Deny(ops.ExfilCanary, "", ops.Slots{Op: "repo.push", By: "git"}), "the task's canary in a local push")
	}
	rep, err := rd.Call(map[string]any{"op": "push.report", "task": req.Task, "repo": RepoName(req.Agent, req.Project), "refs": refs,
		"secrets": scan.Secrets}, 30*time.Second)
	if err != nil {
		if rep != nil && rep["reason"] == "task_ended" {
			return refuse(ops.Deny(ops.TaskEnded, "", ops.Slots{Op: "repo.push", By: "git"}), "")
		}
		// without rootd's answer the push's taint is unknown: fail closed
		return refuse(ops.Deny(ops.AuditUnavailable, "", ops.Slots{Op: "repo.push", By: "git"}), "push.report: "+err.Error())
	}
	if rep["tainted"] == true {
		if err := markTainted(db, RepoName(req.Agent, req.Project), req.Task, refs, scan.Commits, now.UnixMilli()); err != nil {
			return fail("the tainted refs were not recorded")
		}
	}
	if err := addToday(db, req.Agent, size, req.DayCap, now); errors.Is(err, errDayCap) {
		return refuse(capDenial(req.DayCap, now), "a concurrent push took the day total over the cap")
	} else if err != nil {
		return fail("the day total was not recorded")
	}
	return 0
}
