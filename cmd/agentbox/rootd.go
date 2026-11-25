package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"agentbox/internal/fw"
	"agentbox/internal/ntfy"
	"agentbox/internal/rootd"
	"agentbox/internal/rootd/accounts"
	"agentbox/internal/rootd/resolve"
	"agentbox/internal/task"
)

// AdminSocket is rootd-admin.sock (§2.1): root and agentbox-admin members.
const AdminSocket = "/run/agentbox-rootd/rootd-admin.sock"

// cmdRootd is agentbox-rootd.service.
func cmdRootd(args []string) error {
	fs := flag.NewFlagSet("rootd", flag.ContinueOnError)
	cfg := rootd.Config{DB: fw.RootdDB, EgressDir: resolve.EgressDir, AuditDir: auditDir,
		AuditSocket: "/run/agentbox-audit/rootd.sock", SealCrash: crashHook()}
	fs.DurationVar(&cfg.ElementTimeout, "element-timeout", 10*time.Minute, "dst set element timeout (Appendix B: 10m; shorter only for test VMs)")
	fs.DurationVar(&cfg.RefillInterval, "refill-interval", 5*time.Minute, "timer refill and ntfy_dst refresh (§6.1: 5m)")
	if exe, err := os.Executable(); err == nil {
		cfg.GenDir = filepath.Join(filepath.Dir(filepath.Dir(exe)), "gen") // <release>/bin/agentbox: the same release's gen/
	}
	fs.StringVar(&cfg.GenDir, "gen-dir", cfg.GenDir, "the generated op registry files rootd checks at start")
	fs.StringVar(&cfg.AuditDir, "audit-dir", cfg.AuditDir, "the audit segments rootd creates and seals (another dir only for test VMs)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if cfg.ElementTimeout < 10*time.Second || cfg.ElementTimeout > 10*time.Minute || cfg.RefillInterval < 5*time.Second || cfg.RefillInterval >= cfg.ElementTimeout {
		return errors.New("rootd: need 10s <= --element-timeout <= 10m and 5s <= --refill-interval < --element-timeout (ntfy_dst must refresh before it expires)")
	}
	cfg.Effects, cfg.RawAudit = testEffects()
	cfg.QuotaHold = os.Getenv("AGENTBOX_TEST_QUOTA_HOLD") // hack/accounts-gate.sh holds a qgroup repair open; test VMs only
	cfg.Tasks = rootd.DefaultTaskConfig()
	// hack/taskenv-gate.sh: tasks run a full image (image/task, with the pinned Go) the gate loads into each agent's
	// podman, instead of the stub skeleton and the host's /usr. Test VMs only.
	if img := os.Getenv("AGENTBOX_TEST_TASK_IMAGE"); img != "" {
		cfg.Tasks.Image, cfg.Tasks.HostUsr = img, nil
		// the gate loads the image; rootd's setup call through the agent's user manager is all that is left
		cfg.Tasks.EnsureImage = func(a rootd.Account, setup bool) error {
			if !setup {
				return nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			return exec.CommandContext(ctx, "systemd-run", "--user", "-M", "ag-"+a.Name+"@", "--wait", "--quiet", "--collect",
				task.Podman, "image", "exists", img).Run()
		}
	}
	cfg.Alert = func(title, msg string) error {
		return ntfy.Publish(ntfy.Socket, ntfy.TokenPath, ntfy.AlertTopic, title, msg)
	}
	return rootd.Run(cfg)
}

// testEffects is the agentboxd gate's fault injection (hack/agentboxd-gate.sh), unset in production. No agent op has
// a week-4 effect, so AGENTBOX_TEST_GATE_EFFECT=<dir> gives file.write one: it writes the content to <dir>/<op id>,
// which shows whether an effect ran. AGENTBOX_TEST_AUDIT_RAW=1 sends INTENT args without their audit classes.
func testEffects() (map[string]rootd.Effect, bool) {
	dir := os.Getenv("AGENTBOX_TEST_GATE_EFFECT")
	raw := os.Getenv("AGENTBOX_TEST_AUDIT_RAW") == "1"
	if dir == "" {
		return nil, raw
	}
	return map[string]rootd.Effect{"file.write": func(id string, args map[string]any) (map[string]any, error) {
		c, _ := args["content"].(string)
		return nil, os.WriteFile(filepath.Join(dir, id), []byte(c), 0o600)
	}}, raw
}

// cmdEgress is the admin CLI for the broker allowlists, over rootd-admin.sock.
func cmdEgress(args []string) error {
	if len(args) == 0 {
		return errors.New("egress: expected list, allow, remove or refill")
	}
	fs := flag.NewFlagSet("egress "+args[0], flag.ContinueOnError)
	req := map[string]any{}
	switch args[0] {
	case "allow", "remove":
		svc := fs.String("svc", "", "broker: keys or git (service.list), or proxy (common.list)")
		entry := fs.String("entry", "", "host:port")
		ack := new(int)
		if args[0] == "allow" {
			fs.IntVar(ack, "ack-secrets", 0, "grant although the workspace scans found this many credentials for the host (the count the refusal reported)")
		}
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		if *svc == "" || *entry == "" {
			return fmt.Errorf("egress %s: --svc and --entry are required", args[0])
		}
		req = map[string]any{"op": "egress." + args[0], "svc": *svc, "entry": *entry}
		if *ack > 0 {
			req["ackSecrets"] = *ack
		}
	case "list", "refill":
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		req["op"] = map[string]string{"list": "egress.list", "refill": "sets.refill"}[args[0]]
	default:
		return fmt.Errorf("egress: unknown subcommand %q", args[0])
	}
	return adminCall(req, "egress")
}

// adminCall sends one request on rootd-admin.sock, prints the reply line, and fails unless it says ok.
func adminCall(req map[string]any, what string) error {
	line, err := adminLine(req, what)
	fmt.Print(printable(string(line))) // its fields can hold names a task chose (rescan hits, secret-scan paths)
	return err
}

// adminLine is adminCall without the print: it returns the reply line.
func adminLine(req map[string]any, what string) ([]byte, error) {
	c, err := net.Dial("unix", AdminSocket)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Minute)) // agent.add and agent.remove wait for agentbox-accounts.service
	// encodeLine: a task new prompt full of '<' stays within rootd's line
	if _, err := c.Write(encodeLine(req)); err != nil {
		return nil, err
	}
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("rootd closed the connection: %v", err)
	}
	var rep struct {
		OK bool `json:"ok"`
	}
	if json.Unmarshal(line, &rep) != nil || !rep.OK {
		return line, errors.New(what + ": refused")
	}
	return line, nil
}

// cmdAgent is the admin CLI for agent accounts (§4.1), over rootd-admin.sock.
func cmdAgent(args []string) error {
	if len(args) == 0 {
		return errors.New("agent: expected list, add or remove")
	}
	fs := flag.NewFlagSet("agent "+args[0], flag.ContinueOnError)
	switch args[0] {
	case "add", "remove":
		name := fs.String("name", "", "agent name: [a-z][a-z0-9-]{0,28}; the user is ag-<name>")
		var disk *uint64
		if args[0] == "add" {
			disk = fs.Uint64("disk-bytes", 0, "the agent's qgroup 1/N exclusive limit (default: a quarter of the pool)")
		}
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		if *name == "" {
			return fmt.Errorf("agent %s: --name is required", args[0])
		}
		a := map[string]any{"name": *name}
		if disk != nil && *disk != 0 {
			a["diskBytes"] = *disk
		}
		return adminCall(map[string]any{"op": "agent." + args[0], "args": a}, "agent "+args[0])
	case "list":
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		return adminCall(map[string]any{"op": "agent.list"}, "agent list")
	}
	return fmt.Errorf("agent: unknown subcommand %q", args[0])
}

// cmdAccounts is agentbox-accounts.service, which rootd starts after agent.add and agent.remove.
func cmdAccounts(args []string) error {
	if len(args) == 0 || args[0] != "apply" {
		return errors.New("accounts: expected apply")
	}
	if err := parse(flag.NewFlagSet("accounts apply", flag.ContinueOnError), args[1:]); err != nil {
		return err
	}
	return applyAccounts(true)
}

func applyAccounts(live bool) error {
	db, err := rootd.OpenDB(fw.RootdDB)
	if err != nil {
		return err
	}
	defer db.Close()
	return accounts.Reconcile(db, live)
}
