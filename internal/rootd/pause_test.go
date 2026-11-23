package rootd

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"agentbox/internal/ids"
	"agentbox/internal/image"
)

// checkPause (#125, #149): only a live pause process of the agent uid, in the agent's user namespace and its user
// manager outside any task unit, keeps pause.pid; anything else is removed and named.
func TestCheckPause(t *testing.T) {
	a := Account{Name: "claude", UID: 70001, SubID: 0x70010000}
	good := map[string]string{
		"status":  "Name:\tpodman\nUid:\t70001\t70001\t70001\t70001\nGid:\t70001\t70001\t70001\t70001\n",
		"uid_map": "         0      70001          1\n         1 1879113728      65536\n",
		"cgroup":  "0::/user.slice/user-70001.slice/user@70001.service/user.slice/podman-pause-1.scope\n",
	}
	for _, c := range []struct {
		name, pid, file, content, want string
	}{
		{"live in the user manager", "4242", "", "", ""},
		{"dead", "4243", "", "", "dead"},
		{"bad pid", "x", "", "", "bad_pid"},
		{"another uid", "4242", "status", "Name:\tsleep\nUid:\t0\t0\t0\t0\n", "wrong_uid"},
		{"no user namespace", "4242", "uid_map", "0 0 4294967295\n", "wrong_userns"},
		{"a namespace the agent made", "4242", "uid_map", "0 70001 1\n", "wrong_userns"},
		{"in a task unit", "4242", "cgroup", "0::/user.slice/user-70001.slice/user@70001.service/app.slice/agentbox-task-T1.service/x\n", "outside_user_manager"},
		{"outside the user manager", "4242", "cgroup", "0::/system.slice/run-u1.service\n", "outside_user_manager"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			run, proc := filepath.Join(dir, "run"), filepath.Join(dir, "proc")
			tmp := filepath.Join(run, "70001", "libpod", "tmp")
			must(t, os.MkdirAll(tmp, 0o700), os.MkdirAll(filepath.Join(proc, "4242"), 0o755))
			for f, s := range good {
				if f == c.file {
					s = c.content
				}
				must(t, os.WriteFile(filepath.Join(proc, "4242", f), []byte(s), 0o644))
			}
			must(t, os.WriteFile(filepath.Join(tmp, "pause.pid"), []byte(c.pid), 0o644))
			why, err := checkPause(run, proc, a)
			if err != nil || why != c.want {
				t.Fatalf("checkPause = %q, %v; want %q", why, err, c.want)
			}
			if _, err := os.Stat(filepath.Join(tmp, "pause.pid")); (err == nil) != (c.want == "") {
				t.Errorf("pause.pid kept: %v; want kept only when live", err == nil)
			}
		})
	}
	dir := t.TempDir()
	if why, err := checkPause(filepath.Join(dir, "run"), dir, a); why != PauseAbsent || err != nil {
		t.Errorf("no runtime dir: %q, %v", why, err)
	}
	tmp := filepath.Join(dir, "run", "70001", "libpod", "tmp")
	must(t, os.MkdirAll(tmp, 0o700))
	if why, err := checkPause(filepath.Join(dir, "run"), dir, a); why != PauseAbsent || err != nil {
		t.Errorf("no pause.pid: %q, %v", why, err)
	}
	// the agent owns its runtime dir: a symlink is never followed, and a planted one is removed
	must(t, os.WriteFile(filepath.Join(dir, "target"), []byte("4242"), 0o644), os.Symlink(filepath.Join(dir, "target"), filepath.Join(tmp, "pause.pid")))
	if why, err := checkPause(filepath.Join(dir, "run"), dir, a); why != "not_regular" || err != nil {
		t.Errorf("symlinked pause.pid: %q, %v", why, err)
	}
	if _, err := os.Lstat(filepath.Join(tmp, "pause.pid")); err == nil {
		t.Error("the symlink is still there")
	}
	if _, err := os.Stat(filepath.Join(dir, "target")); err != nil {
		t.Error("its target was removed")
	}
	must(t, os.RemoveAll(filepath.Join(dir, "run", "70001", "libpod")), os.Symlink(dir, filepath.Join(dir, "run", "70001", "libpod")))
	if _, err := checkPause(filepath.Join(dir, "run"), dir, a); err == nil {
		t.Error("a symlinked libpod dir was followed")
	}
}

// ensurePodman runs before every launch: a stale pause.pid is audited, and the setup call runs unless the pause
// process is live (#149); podman's "cannot set user namespace" is the typed reason podman_userns (#125), and an
// image.Refused carries its code.
func TestEnsurePodman(t *testing.T) {
	r := newRig(t)
	var setups []bool
	why, imgErr := "", error(nil)
	r.t.cfg.Pause = func(Account) (string, error) { return why, nil }
	r.t.cfg.EnsureImage = func(_ Account, setup bool) error { setups = append(setups, setup); return imgErr }
	for _, w := range []string{PauseAbsent, "", "dead", ""} {
		why = w
		if rep := r.t.start(ids.New(ids.Task), "claude", "daemon"); rep["ok"] != true {
			t.Fatalf("pause %q: %v", w, rep)
		}
	}
	if !slices.Equal(setups, []bool{true, false, true, false}) {
		t.Errorf("setup calls = %v", setups)
	}
	n := 0
	for _, m := range r.records {
		if m["type"] == "PAUSE_PID_STALE" {
			n++
			if m["agent"] != "claude" || m["reason"] != "dead" {
				t.Errorf("record %v", m)
			}
		}
	}
	if n != 1 {
		t.Errorf("%d PAUSE_PID_STALE records, want 1 (none for an absent file)", n)
	}
	why, imgErr = "dead", errors.New("exit status 125: Error: cannot set user namespace")
	if rep := r.t.start(ids.New(ids.Task), "claude", "daemon"); rep["reason"] != "podman_userns" || !strings.Contains(rep["error"].(string), "user namespace") {
		t.Errorf("userns failure: %v", rep)
	}
	why, imgErr = "", errors.New("exit status 1")
	if rep := r.t.start(ids.New(ids.Task), "claude", "daemon"); rep["reason"] != "launch_failed" {
		t.Errorf("other failure: %v", rep)
	}
	// a refused task image is a typed reply (#102, #109)
	imgErr = &image.Refused{Code: image.BlobMismatch, Detail: "x"}
	if rep := r.t.start(ids.New(ids.Task), "claude", "daemon"); rep["reason"] != "image_refused" || rep["code"] != image.BlobMismatch {
		t.Errorf("image refusal: %v", rep)
	}
}

func must(t *testing.T, errs ...error) {
	t.Helper()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}
