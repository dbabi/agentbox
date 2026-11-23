package rootd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"agentbox/internal/denial"
	"agentbox/internal/ops"
	"agentbox/internal/rootd/accounts"
	"agentbox/internal/rootd/attach"
)

// lookupAgent is ag-<name>'s uid and gid; tests replace it.
var lookupAgent = func(name string) (int, int, error) {
	u, err := user.Lookup("ag-" + name)
	if err != nil {
		return 0, 0, err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return uid, gid, nil
}

// attach is agent.attach (§4.2): rootd owns the session PTY and relays its output through the filter. Before the
// session: the task block, INTENT, and the session registered as a tainted writer of workspace:<agent>#<N> (§5.2). After
// it: the token scan, which lifts the block only when the workspace holds no session-home token.
func (s *server) attach(c *net.UnixConn, r request, pending []byte) {
	refuse := func(format string, a ...any) {
		msg := fmt.Sprintf(format, a...)
		log.Printf("agent.attach %s: refused: %s", r.Name, msg)
		c.Write(encode(reply{"ok": false, "error": msg}))
	}
	if !agentRe.MatchString(r.Name) || r.Workspace != "" && r.Workspace != r.Name {
		refuse("bad agent or workspace name (one workspace per agent: data/workspaces/<agent>)")
		return
	}
	if rep := s.fenceDeny("agent.attach"); rep != nil {
		c.Write(encode(rep))
		return
	}
	if r.CLI == "" {
		r.CLI = "claude"
	}
	if r.Rows <= 0 || r.Rows > 1000 || r.Cols <= 0 || r.Cols > 1000 {
		r.Rows, r.Cols = 24, 80
	}
	uid, gid, err := lookupAgent(r.Name)
	if err != nil {
		refuse("no user ag-%s (agent.add makes it)", r.Name)
		return
	}
	root := s.attachRoot()
	id, opID := denial.NewID("ses"), denial.NewID("op")
	start := time.Now()
	if err := attach.Begin(s.db, r.Name, id, start); err != nil {
		refuse("%v", err)
		return
	}
	s.live.Store(r.Name, id)
	defer s.live.Delete(r.Name)
	unblock := func() { attach.End(s.db, r.Name, id, nil) } // nothing ran: no scan to wait for
	p := attach.AgentPaths(root, r.Name, id)
	// the control-path gate (§4.2), after Begin: no task can change the workspace from here on, and only an attach
	// writes session-home
	cur, err := attach.Controls(p)
	var changed []string
	if err == nil {
		changed, err = attach.ControlChanges(s.db, r.Name, cur)
	}
	if err == nil && len(changed) > 0 {
		if !r.AckControlChanges {
			unblock()
			list := changed
			if len(list) > 50 {
				list = append(list[:50:50], fmt.Sprintf("... %d more", len(changed)-50))
			}
			refuse("workspace or session-home control paths changed since the last accepted state: %s; review them, then attach with --ack-control-changes",
				strings.Join(list, ", "))
			return
		}
		err = attach.SaveBaseline(s.db, r.Name, cur)
		log.Printf("agent.attach %s: %d control path change(s) acknowledged", r.Name, len(changed))
	}
	if err != nil {
		unblock()
		refuse("control paths: %v", err)
		return
	}
	o, _ := ops.Lookup("agent.attach")
	args := map[string]any{"name": r.Name, "workspace": r.Name}
	holder, ws := "session:"+id, accounts.WorkspaceSubject(r.Name, uid)
	if err := s.audit(map[string]any{"type": "INTENT", "opId": opID, "name": o.Name, "origin": "admin", "args": ops.Classify(o.Args, args)}); err != nil {
		unblock()
		refuse("audit: the INTENT was not ACKed, no session: %v", err)
		return
	}
	result := func(status, detail string) {
		if err := s.audit(map[string]any{"type": "RESULT", "opId": opID, "status": status, "detail": detail}); err != nil {
			log.Printf("agent.attach %s %s: RESULT not audited: %v", r.Name, id, err)
		}
	}
	// the session's output taints, so it registers as a writer first and is tainted before any byte runs (§5.2)
	for _, rec := range []map[string]any{{"type": "WRITER_ADD", "holder": holder, "workspace": ws},
		{"type": "TAINT", "subject": holder, "source": "attach"}} {
		if err := s.audit(rec); err != nil {
			s.audit(map[string]any{"type": "WRITER_DEL", "holder": holder})
			unblock()
			result("failed", "taint not registered")
			refuse("audit: %s not ACKed, no session: %v", rec["type"], err)
			return
		}
	}
	master, slave, err := attach.OpenPTY(uid, r.Rows, r.Cols)
	var sess attach.Session
	if err == nil {
		sess, err = attach.Prepare(root, id, r.Name, r.CLI, r.Argv, uid, gid, slave.Name(), r.Term)
	}
	defer attach.RemoveRun(p)
	if err != nil {
		if master != nil {
			master.Close()
			slave.Close()
		}
		s.audit(map[string]any{"type": "WRITER_DEL", "holder": holder})
		unblock()
		result("failed", err.Error())
		refuse("%v", err)
		return
	}
	defer master.Close()
	seen := s.agentSeen(r.Name)
	seen.Add(attach.Tokens(p.SessionHome)) // before the session can rotate it
	s.watched.Store(r.Name, id)
	stop := make(chan struct{})
	watched := make(chan struct{})
	go func() { seen.Watch(p.SessionHome, 2*time.Second, stop); close(watched) }()

	log.Printf("agent.attach %s: session %s on %s, cli %s", r.Name, id, slave.Name(), r.CLI)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.SetReadDeadline(time.Time{})
	if _, err := c.Write(encode(reply{"ok": true, "session": id})); err != nil {
		cancel()
	}
	var wg sync.WaitGroup
	wg.Add(1)
	out := make(chan struct{})
	first := &firstRead{r: master, ch: make(chan struct{})}
	go func() { // admin input, as typed; EOF stops input only
		defer wg.Done()
		// podman -t sets the PTY raw with TCSAFLUSH, which drops input not yet read: hold it until the session writes
		select {
		case <-first.ch:
		case <-out:
		case <-time.After(30 * time.Second):
		}
		if len(pending) > 0 {
			master.Write(pending)
		}
		io.Copy(master, c)
	}()
	go func() { // session output, filtered; a gone admin stops the session
		defer close(out)
		if _, err := io.Copy(attach.NewFilter(c), first); err != nil && !errors.Is(err, syscall.EIO) {
			log.Printf("agent.attach %s %s: relay: %v", r.Name, id, err)
		}
		cancel()
	}()
	runErr := s.cfg.Attach.Run(ctx, sess)
	slave.Close() // the session's processes are gone: the master now drains to EIO
	select {
	case <-out:
	case <-time.After(5 * time.Second):
		log.Printf("agent.attach %s %s: output did not drain", r.Name, id)
	}
	close(stop)
	<-watched

	hits, serr := attach.Scan(p.Workspace, start, seen.All())
	status := "token scan: clean, tasks may start"
	switch {
	case serr != nil:
		// the block stays attach_live: an unfinished scan must not let a task start
		status = "token scan failed, tasks stay blocked: " + serr.Error()
		log.Printf("agent.attach %s %s: %s", r.Name, id, status)
		s.alert(r.Name, "token scan failed after an attach; tasks stay blocked")
	case len(hits) > 0:
		status = fmt.Sprintf("%d workspace file(s) hold a session-home token: tasks blocked (agentbox attach status)", len(hits))
		log.Printf("agent.attach %s %s: token scan hit: %v", r.Name, id, hits)
		s.alert(r.Name, status)
		fallthrough
	default:
		if err := attach.End(s.db, r.Name, id, hits); err != nil {
			log.Printf("agent.attach %s %s: task block: %v", r.Name, id, err)
		}
	}
	if err := s.audit(map[string]any{"type": "WRITER_DEL", "holder": holder}); err != nil {
		log.Printf("agent.attach %s %s: WRITER_DEL not audited: %v", r.Name, id, err)
	}
	detail := ""
	if runErr != nil {
		detail = runErr.Error()
	}
	result("executed", detail)
	log.Printf("agent.attach %s: session %s ended (%v); %s", r.Name, id, runErr, status)
	c.Write([]byte("\r\n[agentbox] session ended; " + status + "\r\n"))
	c.CloseWrite()
	c.SetReadDeadline(time.Now().Add(5 * time.Second)) // the admin's side closes once it has read the end
	wg.Wait()
}

// firstRead closes ch once its reader has returned a byte.
type firstRead struct {
	r    io.Reader
	ch   chan struct{}
	once sync.Once
}

func (f *firstRead) Read(p []byte) (int, error) {
	n, err := f.r.Read(p)
	if n > 0 {
		f.once.Do(func() { close(f.ch) })
	}
	return n, err
}
