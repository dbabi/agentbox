package git

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"agentbox/internal/ids"
	"agentbox/internal/ops"
)

// lineCall writes req as one JSON line on the Unix socket sock and returns the one reply line, decoded.
// shortcut: auditd's own client (audit.Send) and pinned dialing's rootd client (internal/dial) land with #21 and #20;
// the service and its hook use these until then.
func lineCall(sock string, req map[string]any, timeout time.Duration) (map[string]any, error) {
	c, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := c.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	line, err := bufio.NewReader(io.LimitReader(c, 1<<20)).ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("no reply: %v", err)
	}
	var rep map[string]any
	if err := json.Unmarshal(line, &rep); err != nil {
		return nil, err
	}
	return rep, nil
}

// Auditor sends records to auditd's git producer socket (§9). Send waits for the ACK: taint and read taint come
// before the bytes they guard.
type Auditor struct{ Sock string }

// Send writes rec and returns nil only on auditd's ACK.
func (a Auditor) Send(rec map[string]any) error {
	rep, err := lineCall(a.Sock, rec, 10*time.Second)
	if err != nil {
		return err
	}
	if rep["ok"] != true {
		return fmt.Errorf("auditd NACK %v", rep["code"])
	}
	return nil
}

// Deny sends a DENY record for d (§9) and ignores the reply: a refusal is not an effect, so no effect waits on it;
// the service calls it on its own goroutine. detail is for humans only: auditd never returns it to an agent.
func (a Auditor) Deny(d ops.Denial, task, agent, detail string) {
	now := time.Now().UnixMilli()
	r := map[string]any{"type": "DENY", "id": d.ID, "code": d.Code, "by": d.By, "count": 1, "first": now, "last": now}
	if d.What != "" {
		r["what"] = d.What
	}
	if d.Op != "" {
		r["op"] = d.Op
	}
	if ids.Is(ids.Task, task) {
		r["task"] = task
	}
	if reAgent.MatchString(agent) {
		r["agent"] = agent
	}
	if d.Subject != nil {
		r["subject"] = d.Subject
	}
	if detail != "" {
		r["detail"] = trunc(detail, 1024)
	}
	a.Send(r)
}

// trunc keeps at most n bytes of s, cut at a byte that starts a UTF-8 sequence, so JSON never widens a cut rune.
func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xc0 == 0x80 {
		n--
	}
	return s[:n]
}

// Rootd is the service's half of resolve-git.sock: name resolution, and the hook's push.report and canary.hit.
type Rootd struct{ Sock string }

// errRootd is a call rootd refused or could not answer.
var errRootd = errors.New("rootd")

// Call sends one request and returns rootd's reply; a reply without ok is an error naming rootd's reason.
func (r Rootd) Call(req map[string]any, timeout time.Duration) (map[string]any, error) {
	rep, err := lineCall(r.Sock, req, timeout)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errRootd, err)
	}
	if rep["ok"] != true {
		return rep, fmt.Errorf("%w: %v", errRootd, rep["reason"])
	}
	return rep, nil
}
