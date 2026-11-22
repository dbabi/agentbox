package rootd

import (
	"bytes"
	"os"
	"path/filepath"
	"time"
)

// populated reads the unit cgroup's cgroup.events; a cgroup that is gone has no processes.
func populated(cg string) bool {
	b, err := os.ReadFile(filepath.Join(cg, "cgroup.events"))
	return err == nil && bytes.Contains(b, []byte("populated 1"))
}

// waitEmpty blocks until cg has no processes ("") or until backstop ("deadline"). watchEvents, when it works, wakes it on
// each cgroup.events change (inotify); the 1 s poll covers a cgroup that is not there yet or a missed event.
func waitEmpty(cg string, backstop time.Time) string {
	wake := watchEvents(filepath.Join(cg, "cgroup.events"))
	for {
		if !populated(cg) {
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
