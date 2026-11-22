package task

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// GateSock is the task's gate socket inside the container.
const GateSock = "/run/agentbox/gate/gate.sock"

// MaxResultOutput is how much of the CLI's stdout taskrun posts: the tail, so the post fits one gate line.
//
// shortcut: the 50 MB output cap needs the bus result rows of weeks 7-8; until then the result carries the last 16 KiB.
const MaxResultOutput = 16 << 10

// Job is the task.fetch reply: what agentboxd dispatched.
type Job struct {
	Task   string `json:"task"`
	CLI    string `json:"cli"`
	Prompt string `json:"prompt"`
}

// Result is the task.result post.
type Result struct {
	Exit      int    `json:"exit"`
	Output    string `json:"output"`
	OutputLen int64  `json:"outputLen"`
}

// Runner is taskrun's environment; tests replace the socket and the clock.
type Runner struct {
	Sock     string
	Home     string
	Exports  string
	Deadline time.Time
	Sleep    func(time.Duration)
	Now      func() time.Time
}

// Call sends one JSON-RPC request on the gate socket and decodes the result into out. Every call retries on ECONNREFUSED
// and ENOENT with capped backoff (1 s to 30 s) until 60 s before the deadline (§4.2): a gate that restarts rebinds its
// socket in the same dir, and the bind mount sees the new one.
func (r *Runner) Call(method string, params, out any) error {
	req, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	wait := time.Second
	for {
		err := r.call(req, out)
		if err == nil || !(errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENOENT)) {
			return err
		}
		if r.Now().Add(wait).After(r.Deadline.Add(-60 * time.Second)) {
			return fmt.Errorf("%s: gate unreachable until 60 s before the deadline: %w", method, err)
		}
		r.Sleep(wait)
		wait = min(2*wait, 30*time.Second)
	}
}

func (r *Runner) call(req []byte, out any) error {
	c, err := net.DialTimeout("unix", r.Sock, 10*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(60 * time.Second))
	if _, err := c.Write(append(req, '\n')); err != nil {
		return err
	}
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("gate closed the connection: %v", err)
	}
	var rep struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &rep); err != nil {
		return fmt.Errorf("gate reply: %v", err)
	}
	if rep.Error != nil {
		return fmt.Errorf("gate: %d %s", rep.Error.Code, rep.Error.Message)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(rep.Result, out)
}

// Setup copies the generated CLI configs from the read-only exports into the tmpfs HOME.
func (r *Runner) Setup() error {
	cp := func(src, dst string) error {
		b, err := os.ReadFile(filepath.Join(r.Exports, src))
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o600)
	}
	if err := cp("claude-settings.json", filepath.Join(r.Home, ".claude", "settings.json")); err != nil {
		return err
	}
	if err := cp("codex-config.toml", filepath.Join(r.Home, ".codex", "config.toml")); err != nil {
		return err
	}
	return os.MkdirAll(filepath.Join(r.Home, ".agentbox"), 0o700)
}

// Taskrun is the container's PID 1 (§4.2): set up HOME, fetch the task, run the CLI with the prompt on stdin, post the
// result. SIGTERM (the unit stopping) goes on to the CLI's process group; systemd SIGKILLs the rest after
// TimeoutStopSec, and the payload is inside the unit's cgroup.
func Taskrun() int {
	dl, _ := strconv.ParseInt(os.Getenv("AGENTBOX_DEADLINE"), 10, 64)
	r := &Runner{Sock: GateSock, Home: os.Getenv("HOME"), Exports: "/opt/agentbox/exports", Deadline: time.UnixMilli(dl),
		Sleep: time.Sleep, Now: time.Now}
	if err := r.Setup(); err != nil {
		fmt.Fprintln(os.Stderr, "taskrun: setup:", err)
		return 1
	}
	var job Job
	if err := r.Call("task.fetch", map[string]any{}, &job); err != nil {
		fmt.Fprintln(os.Stderr, "taskrun:", err)
		return 1
	}
	argv, err := CLIArgv(job.CLI)
	if err != nil {
		fmt.Fprintln(os.Stderr, "taskrun:", err)
		return 1
	}
	code, out, n := r.run(argv, job.Prompt)
	if err := r.Call("task.result", Result{Exit: code, Output: out, OutputLen: n}, nil); err != nil {
		fmt.Fprintln(os.Stderr, "taskrun:", err)
		return 1
	}
	return code
}

// run starts the CLI in its own process group in /workspace and reaps every child until it exits: as PID 1, taskrun
// inherits the CLI's orphans. stdout goes to a file in HOME, not a pipe, so an orphan holding it open can't stall the post.
func (r *Runner) run(argv []string, prompt string) (int, string, int64) {
	outPath := filepath.Join(r.Home, ".agentbox", "output")
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600)
	if err != nil {
		return 127, err.Error(), 0
	}
	defer f.Close()
	in, w, err := os.Pipe()
	if err != nil {
		return 127, err.Error(), 0
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir, cmd.Stdin, cmd.Stdout, cmd.Stderr = "/workspace", in, f, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	if err := cmd.Start(); err != nil {
		in.Close()
		w.Close()
		return 127, err.Error(), 0
	}
	in.Close()
	go func() { io.WriteString(w, prompt); w.Close() }()
	go func() {
		for s := range sig {
			syscall.Kill(-cmd.Process.Pid, s.(syscall.Signal))
		}
	}()
	code := reap(cmd.Process.Pid)
	n, _ := f.Seek(0, io.SeekEnd)
	off := max(0, n-MaxResultOutput)
	b := make([]byte, n-off)
	f.ReadAt(b, off)
	return code, string(b), n
}

// reap waits for any child until pid exits, and returns pid's exit code (128+signal if killed).
func reap(pid int) int {
	for {
		var ws syscall.WaitStatus
		p, err := syscall.Wait4(-1, &ws, 0, nil)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return 127
		}
		if p != pid {
			continue
		}
		if ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return ws.ExitStatus()
	}
}
