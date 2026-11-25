package rootd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"agentbox/internal/rootd/accounts"
)

// PauseAbsent is checkPause's answer when the agent's podman has no pause.pid yet.
const PauseAbsent = "absent"

// checkPause is the cheap check before every launch and attach (§4.2). Rootless podman keeps the agent's user
// namespace in a pause process named by <runDir>/<uid>/libpod/tmp/pause.pid. That process must live in the agent's
// user manager: one a task's podman makes lands in the task unit, and task.stop kills it. And podman 5.7 joins
// whatever process holds that PID, so a reused PID fails every podman call with "cannot set user namespace".
// It returns "" when pause.pid names a live process of the agent uid, in the agent's user namespace, in its user
// manager and outside any task unit; PauseAbsent with no pause.pid; otherwise why not, after removing the file.
// The agent owns <runDir>/<uid>, so every step is a no-follow open.
func checkPause(runDir, proc string, a Account) (string, error) {
	uid := strconv.Itoa(int(a.UID))
	dfd := -1
	for i, name := range []string{runDir, uid, "libpod", "tmp"} {
		at := unix.AT_FDCWD
		if i > 0 {
			at = dfd
		}
		fd, err := unix.Openat(at, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if dfd >= 0 {
			unix.Close(dfd)
		}
		if errors.Is(err, unix.ENOENT) {
			return PauseAbsent, nil
		}
		if err != nil {
			return "", fmt.Errorf("pause.pid: %s: %v", name, err)
		}
		dfd = fd
	}
	defer unix.Close(dfd)
	why, err := pauseWhy(dfd, proc, a)
	if errors.Is(err, unix.ENOENT) {
		return PauseAbsent, nil
	}
	if err != nil {
		return "", err
	}
	if why != "" {
		if err := unix.Unlinkat(dfd, "pause.pid", 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return "", fmt.Errorf("pause.pid: remove: %v", err)
		}
	}
	return why, nil
}

func pauseWhy(dfd int, proc string, a Account) (string, error) {
	fd, err := unix.Openat(dfd, "pause.pid", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ELOOP) {
		return "not_regular", nil
	}
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), "pause.pid")
	defer f.Close()
	if fi, err := f.Stat(); err != nil {
		return "", err
	} else if !fi.Mode().IsRegular() {
		return "not_regular", nil
	}
	b := make([]byte, 32)
	n, _ := f.Read(b)
	pid, err := strconv.Atoi(strings.TrimSpace(string(b[:n])))
	if err != nil || pid <= 1 {
		return "bad_pid", nil
	}
	var pf [3]string // status, uid_map, cgroup
	for i, name := range []string{"status", "uid_map", "cgroup"} {
		b, err := os.ReadFile(filepath.Join(proc, strconv.Itoa(pid), name))
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
			return "dead", nil
		}
		if err != nil { // the process may be live (EMFILE, ENOMEM): keep pause.pid, and fail the launch or attach (#222)
			return "", fmt.Errorf("pause.pid: %v", err)
		}
		pf[i] = string(b)
	}
	u := strconv.Itoa(int(a.UID))
	if !strings.Contains(pf[0], "\nUid:\t"+u+"\t"+u+"\t"+u+"\t"+u+"\n") {
		return "wrong_uid", nil
	}
	// uid 0 is the agent and 1-65536 its sub-id block (/etc/subuid): the namespace podman made, not one the agent did
	if strings.Join(strings.Fields(pf[1]), " ") != fmt.Sprintf("0 %d 1 1 %d %d", a.UID, a.SubID, accounts.SubSize) {
		return "wrong_userns", nil
	}
	mgr := "0::/user.slice/user-" + u + ".slice/user@" + u + ".service/"
	if !strings.HasPrefix(pf[2], mgr) || strings.Contains(pf[2], "/agentbox-task-") {
		return "outside_user_manager", nil
	}
	return "", nil
}
