package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"time"

	"agentbox/internal/gate"
	"agentbox/internal/rootd"
	"agentbox/internal/task"
)

// cmdTask is the human side of tasks (§4.2), on rootd-admin.sock: new reads the prompt on stdin.
func cmdTask(args []string) error {
	if len(args) == 0 {
		return errors.New("task: expected new, stop or list")
	}
	fs := flag.NewFlagSet("task "+args[0], flag.ContinueOnError)
	req := map[string]any{"op": "task." + args[0]}
	switch args[0] {
	case "new":
		agent := fs.String("agent", "", "the agent that runs it")
		cli := fs.String("cli", "claude", "claude, codex or opencode")
		asks := fs.Int("asks", rootd.DefaultAsks, "the task's ask budget, 0 to 10")
		deadline := fs.Duration("deadline", rootd.DefaultDeadline, "how long it may run, at most 2h")
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		p, err := io.ReadAll(io.LimitReader(os.Stdin, gate.MaxPrompt+1))
		if err != nil {
			return err
		}
		if len(p) > gate.MaxPrompt {
			return fmt.Errorf("task new: the prompt on stdin is over %d bytes", gate.MaxPrompt)
		}
		req["agent"], req["cli"], req["asks"], req["deadline"], req["prompt"] = *agent, *cli, *asks, deadline.String(), string(p)
	case "stop":
		id := fs.String("task", "", "task id")
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		req["task"] = *id
	case "list":
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
	default:
		return fmt.Errorf("task: unknown subcommand %q", args[0])
	}
	return adminCall(req)
}

// adminCall sends one request on rootd-admin.sock and prints the reply.
func adminCall(req map[string]any) error {
	line, err := lineCall(AdminSocket, req, 90*time.Second)
	if err != nil {
		return err
	}
	os.Stdout.Write(line)
	var rep struct {
		OK bool `json:"ok"`
	}
	if json.Unmarshal(line, &rep) != nil || !rep.OK {
		return errors.New("refused")
	}
	return nil
}

// cmdAgent is the accounts stand-in: `agentbox agent add` as root, until the accounts area's rootd agent.add.
func cmdAgent(args []string) error {
	if len(args) == 0 || args[0] != "add" {
		return errors.New("agent: expected add")
	}
	fs := flag.NewFlagSet("agent add", flag.ContinueOnError)
	name := fs.String("name", "", "agent name: the user is ag-<name>")
	if err := parse(fs, args[1:]); err != nil {
		return err
	}
	if os.Getuid() != 0 {
		return errors.New("agent add: run as root")
	}
	if err := rootd.StubAdd(*name); err != nil {
		return err
	}
	fmt.Printf("agent %s: ag-%s ready\n", *name, *name)
	return nil
}

// cmdTaskrun is the task container's PID 1.
func cmdTaskrun(args []string) error {
	if err := parse(flag.NewFlagSet("taskrun", flag.ContinueOnError), args); err != nil {
		return err
	}
	os.Exit(task.Taskrun())
	return nil
}

// cmdBrokerStub stands in for a broker (proxy, keys or git, weeks 7-8) on a test box: it binds each task's
// /run/agentbox-<svc>/t/<task>/<svc>.sock on rootd's register, rebinds rootd's live tasks at start, and answers every
// line with its pid, so a task sees a restart as a new pid on the same socket path.
func cmdBrokerStub(args []string) error {
	fs := flag.NewFlagSet("broker-stub", flag.ContinueOnError)
	svc := fs.String("svc", "", "proxy, keys or git")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *svc != "proxy" && *svc != "keys" && *svc != "git" {
		return errors.New("broker-stub: --svc must be proxy, keys or git")
	}
	ls, err := listenFDs()
	if err != nil {
		return err
	}
	ctl, ok := ls["svc-"+*svc]
	if !ok {
		return errors.New("broker-stub: want the svc-" + *svc + " socket from systemd")
	}
	pid := strconv.Itoa(os.Getpid())
	s := &gate.Server{Dir: "/run/agentbox-" + *svc, Name: *svc, AgentIDs: func(a string) (uint32, uint32, error) { return uidOf("ag-" + a) },
		Handle: func(t string, _ []byte) []byte {
			return []byte(`{"ok":true,"svc":"` + *svc + `","task":"` + t + `","pid":` + pid + `}`)
		}}
	if l, err := lineCall("/run/agentbox-rootd/resolve-"+*svc+".sock", map[string]any{"op": "task.list_live"}, 10*time.Second); err != nil {
		log.Printf("task.list_live: %v", err)
	} else if err := s.Rebind(l); err != nil {
		log.Print(err)
	}
	sdNotify("READY=1")
	return s.ServeControl(ctl)
}
