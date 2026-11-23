package main

import (
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
		return errors.New("task: expected new, stop, list or undo")
	}
	fs := flag.NewFlagSet("task "+args[0], flag.ContinueOnError)
	req := map[string]any{"op": "task." + args[0]}
	switch args[0] {
	case "new":
		agent := fs.String("agent", "", "the agent that runs it")
		cli := fs.String("cli", "claude", "claude or codex")
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
	case "undo":
		id := fs.String("task", "", "the task whose start snapshot the workspace goes back to")
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		req["task"] = *id
	default:
		return fmt.Errorf("task: unknown subcommand %q", args[0])
	}
	return adminCall(req, "task "+args[0])
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
