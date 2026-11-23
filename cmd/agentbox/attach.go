package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"time"
)

// cmdAttach is the admin side of agent.attach (ARCHITECTURE.md §4.2): rootd runs the session on a PTY it owns and
// relays the filtered output here. status and rescan show and lift the task block the token scan leaves.
func cmdAttach(args []string) error {
	if len(args) > 0 && (args[0] == "status" || args[0] == "rescan") {
		fs := flag.NewFlagSet("attach "+args[0], flag.ContinueOnError)
		agent := fs.String("agent", "", "agent name")
		ack := fs.Bool("ack-restart", false, "rescan: lift a clean block although rootd restarted since that attach (check the workspace first)")
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		if args[0] == "status" {
			return adminCall(map[string]any{"op": "attach.status"}, "attach status")
		}
		if *agent == "" {
			return errors.New("attach rescan: --agent is required")
		}
		return adminCall(map[string]any{"op": "attach.rescan", "name": *agent, "ackRestart": *ack}, "attach rescan")
	}
	var extra []string
	if i := slices.Index(args, "--"); i >= 0 {
		args, extra = args[:i], args[i+1:]
	}
	fs := flag.NewFlagSet("attach", flag.ContinueOnError)
	agent := fs.String("agent", "", "agent name")
	cli := fs.String("cli", "claude", "claude, codex or bash")
	ack := fs.Bool("ack-control-changes", false, "accept the workspace and session-home control-path changes rootd listed")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *agent == "" {
		return errors.New("attach: --agent is required")
	}
	rows, cols := termSize(os.Stdout)
	c, err := net.Dial("unix", AdminSocket)
	if err != nil {
		return err
	}
	defer c.Close()
	req := map[string]any{"op": "agent.attach", "name": *agent, "cli": *cli, "argv": extra, "rows": rows, "cols": cols, "term": os.Getenv("TERM"),
		"ackControlChanges": *ack}
	b, _ := json.Marshal(req)
	c.SetDeadline(time.Now().Add(60 * time.Second))
	if _, err := c.Write(append(b, '\n')); err != nil {
		return err
	}
	r := bufio.NewReader(c)
	line, err := r.ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("rootd closed the connection: %v", err)
	}
	var rep struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if json.Unmarshal(line, &rep) != nil || !rep.OK {
		return fmt.Errorf("attach: refused: %s", rep.Error)
	}
	c.SetDeadline(time.Time{})
	restore := rawTerm(os.Stdin)
	defer restore()
	go func() {
		io.Copy(c, os.Stdin)
		c.(*net.UnixConn).CloseWrite() // the session keeps running; rootd stops forwarding input
	}()
	_, err = io.Copy(os.Stdout, r)
	return err
}
