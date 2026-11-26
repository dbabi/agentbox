package rootd

import (
	"errors"
	"os"
	"strconv"
	"testing"
)

// #273: the sockets come from the units, so a missing, miscounted or unexpected one is a refusal, which systemd never
// restarts, not an error rootd would hit again at every restart.
func TestListenersRefuse(t *testing.T) {
	pid := strconv.Itoa(os.Getpid())
	for _, env := range [][3]string{
		{"", "", ""},                  // not run by systemd
		{pid, "0", ""},                // no sockets
		{pid, "2", "admin"},           // a name short
		{pid, "1", "resolve-unknown"}, // a socket rootd has no use for
	} {
		t.Setenv("LISTEN_PID", env[0])
		t.Setenv("LISTEN_FDS", env[1])
		t.Setenv("LISTEN_FDNAMES", env[2])
		if _, err := listeners(); !errors.Is(err, ErrRefused) {
			t.Errorf("LISTEN_PID=%q LISTEN_FDS=%q LISTEN_FDNAMES=%q: %v", env[0], env[1], env[2], err)
		}
	}
}
