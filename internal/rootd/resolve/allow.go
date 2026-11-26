package resolve

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"agentbox/internal/rootd/gens"
)

// EgressDir holds the allowlists (§6.2): service.list for the keys and git brokers ("<svc> <host>:<port>" lines),
// common.list and <agent>.list for the proxy ("<host>:<port>" lines). # starts a comment.
const EgressDir = "/var/lib/agentbox/control/egress"

// Brokers are the services with a resolve-<svc>.sock. ntfy's set is rootd's own (NtfyEntry).
var Brokers = []string{"proxy", "keys", "git"}

// NtfyEntry is the one ntfy_dst entry, refreshed by rootd's timer (§6.1).
var NtfyEntry = Entry{"ntfy.sh", 443}

// deputyHosts are never in common.list (§6.2): only a human adds them, per agent.
var deputyHosts = []string{"proxy.golang.org", "sum.golang.org"}

// Lists is the allowlist state rootd checks every resolution against.
type Lists struct {
	Service map[string][]Entry // keys, git
	Common  []Entry
	Agent   map[string][]Entry
}

// Allowed reports whether svc may resolve e; the proxy needs the calling task's agent.
func (l *Lists) Allowed(svc, agent string, e Entry) bool {
	switch svc {
	case "ntfy":
		return e == NtfyEntry
	case "proxy":
		return slices.Contains(l.Common, e) || (agent != "" && slices.Contains(l.Agent[agent], e))
	}
	return slices.Contains(l.Service[svc], e)
}

// AllowedAny is Allowed for any agent: an answer stays in proxy_dst while some list still names its entry.
func (l *Lists) AllowedAny(svc string, e Entry) bool {
	if svc == "proxy" {
		for a := range l.Agent {
			if l.Allowed(svc, a, e) {
				return true
			}
		}
	}
	return l.Allowed(svc, "", e)
}

func readList(p string, withSvc bool) ([][2]string, error) {
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out [][2]string
	sc := bufio.NewScanner(bytes.NewReader(b))
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
			continue
		case withSvc && len(f) == 2:
			out = append(out, [2]string{f[0], f[1]})
		case !withSvc && len(f) == 1:
			out = append(out, [2]string{"", f[0]})
		default:
			return nil, fmt.Errorf("%s:%d: bad line", p, n)
		}
	}
	return out, sc.Err()
}

// LoadLists reads dir. Any bad line fails the whole load: rootd then resolves nothing rather than a partial list.
func LoadLists(dir string) (*Lists, error) {
	l := &Lists{Service: map[string][]Entry{}, Agent: map[string][]Entry{}}
	svc, err := readList(filepath.Join(dir, "service.list"), true)
	if err != nil {
		return nil, err
	}
	for _, r := range svc {
		if r[0] != "keys" && r[0] != "git" {
			return nil, fmt.Errorf("service.list: unknown service %q (keys or git)", r[0])
		}
		e, err := ParseEntry(r[1])
		if err != nil {
			return nil, fmt.Errorf("service.list: %v", err)
		}
		l.Service[r[0]] = append(l.Service[r[0]], e)
	}
	names, err := filepath.Glob(filepath.Join(dir, "*.list"))
	if err != nil {
		return nil, err
	}
	for _, p := range names {
		base := strings.TrimSuffix(filepath.Base(p), ".list")
		if base == "service" {
			continue
		}
		rows, err := readList(p, false)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			e, err := ParseEntry(r[1])
			if err != nil {
				return nil, fmt.Errorf("%s.list: %v", base, err)
			}
			if base == "common" {
				if slices.Contains(deputyHosts, e.Host) {
					return nil, fmt.Errorf("common.list names deputy host %s: only a human adds it, per agent (§6.2)", e.Host)
				}
				l.Common = append(l.Common, e)
			} else {
				l.Agent[base] = append(l.Agent[base], e)
			}
		}
	}
	return l, nil
}

// listFile is where an admin egress change for svc lands: service.list for keys and git, common.list for the proxy.
func listFile(dir, svc string) (string, bool) {
	switch svc {
	case "keys", "git":
		return filepath.Join(dir, "service.list"), true
	case "proxy":
		return filepath.Join(dir, "common.list"), false
	}
	return "", false
}

// editMu serializes EditList: two edits that both read the old file would each write back a copy without the other's
// change, and a finished removal would come back.
var editMu sync.Mutex

// EditList adds (add=true) or removes e for svc and writes the file atomically. It reports whether anything changed.
// Rows match on the Entry LoadLists parses from them, so a removal takes every row that names e, in any spelling, and
// the file is written back in canonical form.
func EditList(dir, svc string, e Entry, add bool) (bool, error) {
	p, withSvc := listFile(dir, svc)
	if p == "" {
		return false, fmt.Errorf("unknown service %q (proxy, keys or git)", svc)
	}
	e, err := ParseEntry(e.String())
	if err != nil {
		return false, err
	}
	if add && svc == "proxy" && slices.Contains(deputyHosts, e.Host) {
		return false, fmt.Errorf("%s is a deputy host: never in common.list (§6.2)", e.Host)
	}
	editMu.Lock()
	defer editMu.Unlock()
	rows, err := readList(p, withSvc)
	if err != nil {
		return false, err
	}
	var b strings.Builder
	b.WriteString("# managed by agentbox egress allow/remove (rootd)\n")
	found := false
	for _, r := range rows {
		re, err := ParseEntry(r[1])
		if err != nil {
			return false, fmt.Errorf("%s: %v", filepath.Base(p), err)
		}
		if re == e && (!withSvc || r[0] == svc) {
			found = true
			if !add {
				continue
			}
		}
		if withSvc {
			b.WriteString(r[0] + " ")
		}
		b.WriteString(re.String() + "\n")
	}
	if add == found {
		return false, nil
	}
	if add {
		if withSvc {
			b.WriteString(svc + " ")
		}
		b.WriteString(e.String() + "\n")
	}
	if err := MkdirEgress(dir); err != nil {
		return false, err
	}
	return true, gens.WriteAtomic(p, []byte(b.String()), 0o644)
}

// MkdirEgress makes the egress dir 0755, whatever the umask: rootd's is 0077, and the brokers, running as their own
// users, read their lists there (#282). It also repairs a dir an earlier release made 0700.
func MkdirEgress(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.Chmod(dir, 0o755)
}
