package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"agentbox/internal/dial"
	"agentbox/internal/git"
)

// cmdGit is agentbox-git.service (ARCHITECTURE.md §2, §6.3): svc-git.sock comes from its .socket unit, the GitHub
// token from its systemd credentials.
func cmdGit(args []string) error {
	fs := flag.NewFlagSet("git", flag.ContinueOnError)
	max := fs.Int64("max-push-bytes", git.MaxPushBytes, "receive.maxInputSize: git's cap on one push")
	api := fs.String("api", "https://"+git.APIHost, "GitHub REST")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := serviceFilter(); err != nil { // git, its hook and http-backend inherit it
		return err
	}
	ls, err := listenFDs()
	if err != nil {
		return err
	}
	ctl, ok := ls["svc-git"]
	if !ok || len(ls) != 1 {
		return errors.New("git: want exactly the svc-git socket from systemd")
	}
	out, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		return fmt.Errorf("git --exec-path: %v (is git installed?)", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	hc := dial.Dialer{Sock: git.ResolveSock}.Client() // pinned dialing (§6.3): rootd's addresses only, no redirect, no cookies
	hc.Timeout = time.Minute                          // one REST call; a push runs under its op's own deadline
	s := &git.Server{Root: git.Root, TaskDir: git.TaskDir, Hooks: git.HooksDir, Backend: filepath.Join(strings.TrimSpace(string(out)), "git-http-backend"),
		MaxPush: *max, AgentIDs: func(a string) (uint32, uint32, error) { return uidOf("ag-" + a) },
		Audit: git.Auditor{Sock: git.AuditSock}, Rootd: git.Rootd{Sock: git.ResolveSock},
		GitHub: &git.GitHub{API: *api, HTTP: hc, Token: git.Token},
		Pusher: git.Pusher{Sock: git.ResolveSock, Helper: "!" + exe + " git-credential", Env: []string{"CREDENTIALS_DIRECTORY=" + os.Getenv("CREDENTIALS_DIRECTORY")}}}
	if _, err := os.Stat(s.Backend); err != nil {
		return fmt.Errorf("git-http-backend: %v", err)
	}
	if err := s.Open(); err != nil {
		return err
	}
	if err := s.Rebind(); err != nil {
		log.Printf("task.list_live: %v: no task sockets rebound", err)
	}
	sdNotify("READY=1")
	return s.ServeControl(ctl)
}

// ownGitStore gives git/ (a subvolume quota.Ensure makes, root's at first) to agentbox-git, mode 0700: the service
// alone reads and writes the repos.
func ownGitStore(dir string) error {
	uid, gid, err := uidOf("agentbox-git")
	if err != nil {
		return fmt.Errorf("no agentbox-git user (sysusers.d/agentbox.conf): %v", err)
	}
	if err := os.Lchown(dir, int(uid), int(gid)); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}

// cmdGitHook is `agentbox git-hook pre-receive`, the release's root-owned hook (git-hooks/pre-receive).
func cmdGitHook(args []string) error {
	if len(args) != 1 || args[0] != "pre-receive" {
		return errors.New("git-hook: expected pre-receive")
	}
	os.Exit(git.Hook(os.Stdin, os.Stdout, os.Stderr, os.Getenv, time.Now()))
	return nil
}

// cmdGitCredential is the git credential helper of agentbox-git's own pushes: `agentbox git-credential get`.
func cmdGitCredential(args []string) error {
	if len(args) != 1 {
		return errors.New("git-credential: expected get, store or erase")
	}
	in, err := io.ReadAll(io.LimitReader(os.Stdin, 64<<10))
	if err != nil {
		return err
	}
	var out bytes.Buffer
	if err := git.Credential(args[0], in, &out); err != nil {
		return err
	}
	_, err = os.Stdout.Write(out.Bytes())
	return err
}

// cmdRemote is the admin CLI for the remotes registry (Appendix E), over rootd-admin.sock.
func cmdRemote(args []string) error {
	if len(args) == 0 {
		return errors.New("remote: expected set or list")
	}
	fs := flag.NewFlagSet("remote "+args[0], flag.ContinueOnError)
	switch args[0] {
	case "set":
		id := fs.String("id", "", "the remote's id, which the agent names in repo.push and gh.*")
		agent := fs.String("agent", "", "the agent that owns it")
		project := fs.String("project", "", "the agent's local repo that pushes to it (made if missing)")
		url := fs.String("url", "", "https://github.com/<owner>/<repo>")
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		if *id == "" || *agent == "" || *project == "" || *url == "" {
			return errors.New("remote set: --id, --agent, --project and --url are required")
		}
		return adminCall(map[string]any{"op": "remote.set", "args": map[string]any{"id": *id, "agent": *agent, "project": *project, "url": *url}}, "remote set")
	case "list":
		agent := fs.String("agent", "", "only this agent's remotes")
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		return adminCall(map[string]any{"op": "remote.list", "agent": *agent}, "remote list")
	}
	return fmt.Errorf("remote: unknown subcommand %q", args[0])
}

// cmdPending is the admin CLI for the asks waiting for a human (§5.4), over rootd-admin.sock.
// shortcut: approve is the admin's own rootd-admin.sock call, not an SSHSIG over H made on the laptop (#24).
func cmdPending(args []string) error {
	if len(args) == 0 {
		return errors.New("pending: expected list, get, approve or deny")
	}
	fs := flag.NewFlagSet("pending "+args[0], flag.ContinueOnError)
	switch args[0] {
	case "list":
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		return adminCall(map[string]any{"op": "pending.list"}, "pending list")
	case "get", "approve", "deny":
		id := fs.String("id", "", "the pending id (pnd_...)")
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		if *id == "" {
			return fmt.Errorf("pending %s: --id is required", args[0])
		}
		if args[0] == "get" {
			return showPending(*id)
		}
		// an approval runs the effect before rootd answers: a push or a GitHub call can take minutes
		line, err := adminLineFor(map[string]any{"op": "pending." + args[0], "id": *id}, "pending "+args[0], 20*time.Minute)
		fmt.Print(printable(string(line)))
		return err
	}
	return fmt.Errorf("pending: unknown subcommand %q", args[0])
}

// cmdApprove is `agentbox approve [--yes] <id>`: it shows P, asks, then approves it.
func cmdApprove(args []string) error {
	fs := flag.NewFlagSet("approve", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "approve without asking")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 1 {
		return errors.New("approve: expected one pending id")
	}
	id := fs.Arg(0)
	if err := showPending(id); err != nil {
		return err
	}
	if !*yes {
		fmt.Print("Approve this op? Type yes: ")
		ans, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if strings.TrimSpace(ans) != "yes" {
			return errors.New("approve: not approved")
		}
	}
	line, err := adminLineFor(map[string]any{"op": "pending.approve", "id": id}, "approve", 20*time.Minute)
	fmt.Print(printable(string(line)))
	return err
}

// showPending prints one pending P for a human (§5.4 CLI rendering): bound and structural fields first, one line each,
// then the agent's text under "untrusted text", quoted with every non-ASCII and control byte escaped.
func showPending(id string) error {
	line, err := adminLine(map[string]any{"op": "pending.get", "id": id}, "pending get")
	if err != nil {
		fmt.Print(printable(string(line)))
		return err
	}
	var rep struct {
		Pending struct {
			ID, Task, Agent, State, Signer, Reason, H string
			Op                                        struct {
				Name string         `json:"name"`
				Args map[string]any `json:"args"`
			} `json:"op"`
			Bound     git.Bound       `json:"bound"`
			Result    json.RawMessage `json:"result"`
			ExpiresAt int64           `json:"expiresAt"`
		} `json:"pending"`
	}
	if err := json.Unmarshal(line, &rep); err != nil {
		return err
	}
	p, b := rep.Pending, rep.Pending.Bound
	q := strconv.QuoteToASCII
	fmt.Printf("pending %s: %s, state %s, expires %s\n", q(p.ID), q(p.Op.Name), q(p.State), time.UnixMilli(p.ExpiresAt).UTC().Format(time.RFC3339))
	fmt.Printf("task %s, agent %s\n", q(p.Task), q(p.Agent))
	if b.URL != "" {
		fmt.Printf("remote %s: %s (%s, node %s)\n", q(b.Remote), q(b.URL), q(b.Visibility), q(b.NodeID))
	}
	if b.Visibility != "" && b.Visibility != "private" {
		fmt.Printf("DELIVERS TO A %s REMOTE\n", strings.ToUpper(b.Visibility))
	}
	for _, kv := range [][2]string{{"project", b.Project}, {"ref", b.Ref}, {"oid", b.OID}, {"base", b.Base}, {"source", b.SrcOID}, {"main now", b.DstOID}} {
		if kv[1] != "" {
			fmt.Printf("%s %s\n", kv[0], q(kv[1]))
		}
	}
	if b.Number != 0 {
		fmt.Printf("number %d\n", b.Number)
	}
	if p.Signer != "" || p.Reason != "" {
		fmt.Printf("signer %s, reason %s\n", q(p.Signer), q(p.Reason))
	}
	if len(p.Result) > 0 && string(p.Result) != "null" {
		fmt.Printf("result %s\n", printable(string(p.Result)))
	}
	fmt.Println("untrusted text:")
	for _, k := range []string{"title", "body"} {
		v, ok := p.Op.Args[k].(string)
		if !ok {
			continue
		}
		fmt.Printf("  %s (%d bytes, %d code points): %s\n", k, len(v), len([]rune(v)), q(v))
	}
	fmt.Printf("H %s\n", q(p.H))
	return nil
}
