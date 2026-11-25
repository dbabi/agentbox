package rootd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// populated reads the unit cgroup's cgroup.events: a cgroup that is gone has no processes. Any other read error counts
// as populated and is returned, so no caller ends a task or lifts its block on a cgroup it could not read (#222).
func populated(cg string) (bool, error) {
	b, err := os.ReadFile(filepath.Join(cg, "cgroup.events"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err != nil || bytes.Contains(b, []byte("populated 1")), err
}

// waitEmpty blocks until cg has no processes ("") or until backstop ("deadline"). watchEvents, when it works, wakes it on
// each cgroup.events change (inotify); the 1 s poll covers a cgroup that is not there yet or a missed event.
func waitEmpty(cg string, backstop time.Time) string {
	wake := watchEvents(filepath.Join(cg, "cgroup.events"))
	for {
		if p, _ := populated(cg); !p {
			return ""
		}
		if !time.Now().Before(backstop) {
			return "deadline"
		}
		select {
		case <-wake:
		case <-time.After(time.Second):
		}
	}
}
