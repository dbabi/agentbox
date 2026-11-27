package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"agentbox/internal/audit"
	"agentbox/internal/broker"
	"agentbox/internal/budgets"
	"agentbox/internal/dial"
	"agentbox/internal/keys"
)

const (
	keysDir         = "/run/agentbox-keys"
	keysResolveSock = "/run/agentbox-rootd/resolve-keys.sock"
	keysAuditSock   = "/run/agentbox-audit/keys.sock"
	keysLedger      = "/var/lib/agentbox/keys/spend.db"
	keysPolicy      = "/var/lib/agentbox/control/keys/server-tools"
	llamaSock       = "/run/agentbox-llm/llama.sock"
)

// cmdKeys is agentbox-keys.service (§2, §6.3, #108): the LLM broker. svc-keys.sock comes from its .socket unit; on
// rootd's register it binds the task's keys.sock in the dir rootd made, and at start it rebinds rootd's live tasks, so
// a running task survives a keys restart (§2.1), the restart a secret.set makes.
func cmdKeys(args []string) error {
	if err := parse(flag.NewFlagSet("keys", flag.ContinueOnError), args); err != nil {
		return err
	}
	if err := serviceFilter(); err != nil {
		return err
	}
	ls, err := listenFDs()
	if err != nil {
		return err
	}
	ctl, ok := ls["svc-keys"]
	if !ok || len(ls) != 1 {
		return errors.New("keys: want exactly the svc-keys socket from systemd")
	}
	creds := os.Getenv("CREDENTIALS_DIRECTORY") // the unit's LoadCredentialEncrypted= values, only this uid's
	if creds == "" {
		return errors.New("keys: no CREDENTIALS_DIRECTORY: run as agentbox-keys.service, which loads the keys (#108)")
	}
	ledger, err := keys.OpenLedger(keysLedger)
	if err != nil {
		return err
	}
	defer ledger.Close()
	tr := dial.Dialer{Sock: keysResolveSock}.Transport()
	tr.DisableCompression = true // keys scans the reply as the vendor sent it
	ks := &keys.Server{Ledger: ledger, Transport: tr,
		Upstream: map[string]string{"anthropic": "https://api.anthropic.com", "openai": "https://api.openai.com"},
		Key:      func(vendor string) string { return credential(creds, keys.CredName[vendor]) },
		Audit:    func(rec map[string]any) error { return audit.Send(keysAuditSock, rec) },
		Limits:   keysLimits, ServerTools: func() []string { return readList(keysPolicy) },
		Local: &keys.Local{Socket: llamaSock, MaxTokens: keys.LocalMaxTokens, Tainted: tainted,
			Recycle: func() error { return rootdKeysCall(map[string]any{"op": "llm.recycle"}, 3*time.Minute) }},
		CanaryHit: func(task string) error {
			return rootdKeysCall(map[string]any{"op": "canary.hit", "task": task}, 10*time.Second)
		}}
	if b := os.Getenv("AGENTBOX_TEST_KEYS_DENY_BETA"); b != "" {
		ks.DenyBetas = strings.Split(b, ",") // test VMs only: see Claude Code retry without a beta it sends (#18)
		log.Printf("keys: refusing beta values %v (AGENTBOX_TEST_KEYS_DENY_BETA)", ks.DenyBetas)
	}
	s := &broker.Server{Name: "keys", Dir: keysDir, By: "keys", Handler: ks.Handler, Format: ks.Format,
		AgentIDs: func(a string) (uint32, uint32, error) { return uidOf("ag-" + a) }}
	if l, err := lineCall(keysResolveSock, map[string]any{"op": "task.list_live"}, 10*time.Second); err != nil {
		log.Printf("task.list_live: %v: no task sockets rebound", err)
	} else if err := s.Rebind(l); err != nil {
		log.Print(err)
	}
	for v, n := range keys.CredName {
		log.Printf("keys: %s key %s", v, map[bool]string{true: "set", false: "not set (agentbox secret set --name " + n + ")"}[credential(creds, n) != ""])
	}
	sdNotify("READY=1")
	return s.ServeControl(ctl)
}

// credential is one loaded credential's value, read at each use: a secret.set restarts the unit with the new one.
func credential(dir, name string) string {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// keysLimits are one request's caps (§6.3): the agent's day share and the box cap from the shares rootd writes, and the
// trace budget from budgets.toml.
func keysLimits(agent string) (keys.Limits, error) {
	sh, err := budgets.ReadShares(budgets.SharesPath)
	if err != nil {
		return keys.Limits{}, err
	}
	b, err := budgets.Read(budgets.Path)
	if err != nil {
		return keys.Limits{}, err
	}
	share, capped := sh.Of(agent)
	return keys.Limits{Agent: keys.Cents(share), Capped: capped, Trace: keys.Cents(b.Get("keys.trace_cents")), Box: keys.Cents(sh.CapCents)}, nil
}

// readList is a file's non-comment lines; a missing file is none.
func readList(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

// rootdKeysCall is one request on resolve-keys.sock.
func rootdKeysCall(req map[string]any, timeout time.Duration) error {
	line, err := lineCall(keysResolveSock, req, timeout)
	if err != nil {
		return err
	}
	var rep struct {
		OK     bool   `json:"ok"`
		Reason string `json:"reason"`
	}
	if json.Unmarshal(line, &rep) != nil || !rep.OK {
		return fmt.Errorf("rootd %s: %s", req["op"], rep.Reason)
	}
	return nil
}

// tainted is rootd's view of a task's effective taint, for the local LLM's instance taint (§6.3).
func tainted(task string) (bool, error) {
	line, err := lineCall(keysResolveSock, map[string]any{"op": "task.tainted", "task": task}, 10*time.Second)
	if err != nil {
		return true, err
	}
	var rep struct {
		OK      bool   `json:"ok"`
		Tainted bool   `json:"tainted"`
		Reason  string `json:"reason"`
	}
	if json.Unmarshal(line, &rep) != nil || !rep.OK {
		return true, fmt.Errorf("rootd task.tainted: %s", rep.Reason)
	}
	return rep.Tainted, nil
}

// cmdSecret is `agentbox secret set --name N` (§4.3, #108): the value comes from standard input (one line, as typed at
// a hidden prompt or piped), never from argv or the environment, and the CLI never prints it.
func cmdSecret(args []string) error {
	if len(args) == 0 || args[0] != "set" {
		return errors.New("secret: expected set")
	}
	fs := flag.NewFlagSet("secret set", flag.ContinueOnError)
	name := fs.String("name", "", "anthropic-api-key, openai-api-key or github-token")
	if err := parse(fs, args[1:]); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("secret set: --name is required")
	}
	restore, prompt := noEcho(os.Stdin)
	if prompt {
		fmt.Fprintf(os.Stderr, "value for %s (not shown): ", *name)
	}
	v, err := bufio.NewReader(io.LimitReader(os.Stdin, 64<<10)).ReadString('\n')
	restore()
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return adminCall(map[string]any{"op": "secret.set", "name": *name, "value": strings.TrimRight(v, "\r\n")}, "secret set")
}
