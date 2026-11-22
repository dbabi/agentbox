package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"agentbox/internal/gate"
	"agentbox/internal/ops"
)

const (
	gateDir       = "/run/agentbox-gate"
	svcGateSock   = "/run/agentbox-rootd/svc-gate.sock"
	rootdGateSock = "/run/agentbox-rootd/rootd.sock"
)

// releaseGen is the running release's gen/: <release>/bin/agentbox, then <release>/gen.
func releaseGen() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(filepath.Dir(exe)), "gen")
}

// cmdAgentboxd is agentboxd.service (§2): the task gate. svc-gate.sock comes from its .socket unit.
func cmdAgentboxd(args []string) error {
	fs := flag.NewFlagSet("agentboxd", flag.ContinueOnError)
	genDir := fs.String("gen-dir", releaseGen(), "the generated op registry files agentboxd checks at start")
	rootdSock := fs.String("rootd-socket", rootdGateSock, "rootd.sock, where gate requests go")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := ops.Check(*genDir); err != nil {
		return fmt.Errorf("op registry mismatch, refusing to start (§5.1): %v", err)
	}
	log.Printf("op registry matches %s: %d ops", *genDir, len(ops.Registry))
	ls, err := listenFDs()
	if err != nil {
		return err
	}
	ctl, ok := ls["svc-gate"]
	if !ok || len(ls) != 1 {
		return errors.New("agentboxd: want exactly the svc-gate socket from systemd")
	}
	s := &gate.Server{Dir: gateDir, Forward: func(req map[string]any) ([]byte, error) { return lineCall(*rootdSock, req, 60*time.Second) },
		AgentIDs: func(agent string) (uint32, uint32, error) { return uidOf("ag-" + agent) }, CLIs: []string{"claude", "codex"}}
	if os.Getenv("AGENTBOX_TEST_CLI") == "sh" {
		s.CLIs = append(s.CLIs, "sh") // test boxes only: the prompt runs as a shell script in the task
	}
	if l, err := lineCall(*rootdSock, map[string]any{"op": "task.list_live"}, 10*time.Second); err != nil {
		log.Printf("task.list_live: %v: no task sockets rebound", err)
	} else if err := s.Rebind(l); err != nil {
		log.Print(err)
	}
	sdNotify("READY=1")
	return s.ServeControl(ctl)
}

// lineCall sends one JSON line on a Unix socket and returns the reply line.
// encodeLine is req as one line with no HTML escaping: json.Marshal would turn each <, > and & in forwarded args into
// 6 bytes, so a request the gate accepted could pass rootd.sock's line limit.
func encodeLine(req any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	e.Encode(req) // Encode ends the line with '\n'
	return b.Bytes()
}

func lineCall(sock string, req any, timeout time.Duration) ([]byte, error) {
	c, err := net.DialTimeout("unix", sock, timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write(encodeLine(req)); err != nil {
		return nil, err
	}
	return bufio.NewReader(c).ReadBytes('\n')
}

// cmdGate is the gate's operator and test CLI: register and revoke stand in for rootd's task.start and task.stop
// (weeks 5-6) on svc-gate.sock, as root; call is a task-side client that sends JSON-RPC lines on a gate socket.
func cmdGate(args []string) error {
	if len(args) == 0 {
		return errors.New("gate: expected register, revoke, list or call")
	}
	fs := flag.NewFlagSet("gate "+args[0], flag.ContinueOnError)
	var req map[string]any
	switch args[0] {
	case "register", "revoke":
		task := fs.String("task", "", "task id")
		agent := fs.String("agent", "", "agent name (register)")
		chain := fs.String("chain", "", "comma-separated ancestor task ids (register)")
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		req = map[string]any{"call": args[0], "task": *task}
		if args[0] == "register" {
			req["agent"] = *agent
			if *chain != "" {
				req["chain"] = strings.Split(*chain, ",")
			}
		}
	case "list":
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		req = map[string]any{"call": "list"}
	case "call":
		sock := fs.String("socket", "", "the task's gate.sock")
		if err := fs.Parse(args[1:]); err != nil {
			return errUsage
		}
		if *sock == "" || fs.NArg() == 0 {
			return errors.New("gate call: --socket and at least one JSON-RPC request are required")
		}
		c, err := net.DialTimeout("unix", *sock, 10*time.Second)
		if err != nil {
			return err
		}
		defer c.Close()
		br := bufio.NewReader(c)
		for _, r := range fs.Args() {
			c.SetDeadline(time.Now().Add(60 * time.Second))
			if _, err := c.Write([]byte(strings.TrimSpace(r) + "\n")); err != nil {
				return err
			}
			line, err := br.ReadBytes('\n')
			if err != nil {
				return fmt.Errorf("no reply: %v", err)
			}
			os.Stdout.Write(line)
		}
		return nil
	default:
		return fmt.Errorf("gate: unknown subcommand %q", args[0])
	}
	line, err := lineCall(svcGateSock, req, 10*time.Second)
	if err != nil {
		return err
	}
	os.Stdout.Write(line)
	var rep struct {
		OK bool `json:"ok"`
	}
	if json.Unmarshal(line, &rep) != nil || !rep.OK {
		return errors.New("gate: refused")
	}
	return nil
}
