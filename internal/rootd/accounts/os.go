package accounts

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"agentbox/internal/rootd/gens"
	"agentbox/internal/rootd/quota"
)

const (
	agentboxBin = "/var/lib/agentbox/current/bin/agentbox"
	unitDir     = "/etc/systemd/system"
	lingerDir   = "/var/lib/systemd/linger"
	// Unit is the oneshot that runs Reconcile live; rootd starts it after each agent.add and agent.remove.
	Unit = "agentbox-accounts.service"
)

// SubidFiles are rewritten from the ids table on every Reconcile.
var SubidFiles = []string{"/etc/subuid", "/etc/subgid"}

func statUID(fi os.FileInfo) int { return int(fi.Sys().(*syscall.Stat_t).Uid) }

func (a Agent) userDropIn() string {
	return fmt.Sprintf("%s/user@%d.service.d/50-agentbox.conf", unitDir, a.UID())
}

func (a Agent) sliceDropIn() string {
	return fmt.Sprintf("%s/user-%d.slice.d/50-agentbox.conf", unitDir, a.UID())
}

// UserDropIn is Appendix C's user@<uid> drop-in: the user manager starts only behind the firewall, reconcile and rootd,
// passes fwcheck, and reads its config (systemd user units included) only from the root-owned XDG dirs.
func (a Agent) UserDropIn() string {
	return `# Written by agentbox from rootd's ids table (ARCHITECTURE.md §4.1, Appendix C).
[Unit]
Requires=agentbox-firewall.service agentbox-reconcile.service agentbox-rootd.service
After=agentbox-firewall.service agentbox-reconcile.service agentbox-rootd.service
[Service]
Environment=XDG_CONFIG_HOME=` + a.XDG() + `/config XDG_DATA_HOME=` + a.XDG() + `/data
ExecStartPre=+` + agentboxBin + ` fwcheck
`
}

// SliceDropIn is Appendix C's per-agent slice limits.
const SliceDropIn = `# Written by agentbox (ARCHITECTURE.md Appendix C).
[Slice]
CPUWeight=100
MemoryHigh=6G
MemoryMax=8G
TasksMax=4096
IOWeight=100
`

func run(name string, args ...string) error {
	_, err := quota.Run(name, args...)
	return err
}

// writeIfChanged writes p root-owned 0644, atomically, unless it already holds content.
func writeIfChanged(p, content string) error {
	_, err := writeChanged(p, content)
	return err
}

func writeChanged(p, content string) (bool, error) {
	if b, err := os.ReadFile(p); err == nil && string(b) == content {
		return false, nil
	}
	if err := mkdirRoot(p[:strings.LastIndexByte(p, '/')], 0o755); err != nil {
		return false, err
	}
	if err := gens.WriteAtomic(p, []byte(content), 0o644); err != nil {
		return false, err
	}
	return true, os.Lchown(p, 0, 0)
}

// RenderSubids rewrites one of /etc/subuid or /etc/subgid: every ag-* line comes from the active agents, by N; any
// other entry is kept, unless it reaches into the agentbox span, which refuses (§4.1).
func RenderSubids(cur []byte, agents []Agent) ([]byte, error) {
	var out bytes.Buffer
	for i, l := range strings.Split(string(cur), "\n") {
		t := strings.TrimSpace(l)
		if t == "" || t[0] == '#' {
			if t != "" {
				out.WriteString(l + "\n")
			}
			continue
		}
		f := strings.Split(t, ":")
		if len(f) != 3 {
			return nil, fmt.Errorf("line %d: not name:start:count", i+1)
		}
		if strings.HasPrefix(f[0], "ag-") {
			continue
		}
		start, err1 := strconv.ParseUint(f[1], 10, 64)
		count, err2 := strconv.ParseUint(f[2], 10, 64)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("line %d: not name:start:count", i+1)
		}
		if start < SubEnd && start+count > SubBase {
			return nil, fmt.Errorf("line %d: %s's range %d+%d overlaps the agentbox sub-id span %#x-%#x", i+1, f[0], start, count, SubBase, SubEnd-1)
		}
		out.WriteString(l + "\n")
	}
	for _, a := range agents {
		if a.Active {
			fmt.Fprintf(&out, "%s:%d:%d\n", a.User(), a.SubID(), SubSize)
		}
	}
	return out.Bytes(), nil
}

// ensureUser creates group and user ag-<name> with uid/gid 70000+N, nologin, and the root-owned home.
func ensureUser(a Agent) error {
	uid := strconv.Itoa(a.UID())
	if u, err := user.LookupId(uid); err == nil && u.Username != a.User() {
		return fmt.Errorf("accounts: uid %s belongs to %s, not %s", uid, u.Username, a.User())
	}
	if u, err := user.Lookup(a.User()); err == nil {
		if u.Uid != uid || u.Gid != uid {
			return fmt.Errorf("accounts: %s has uid %s gid %s, want %s", a.User(), u.Uid, u.Gid, uid)
		}
		return nil
	}
	if g, err := user.LookupGroupId(uid); err == nil && g.Name != a.User() {
		return fmt.Errorf("accounts: gid %s belongs to group %s, not %s", uid, g.Name, a.User())
	} else if err != nil {
		if err := run("groupadd", "-g", uid, a.User()); err != nil {
			return err
		}
	}
	return run("useradd", "-u", uid, "-g", uid, "-d", a.Home(), "-M", "-s", "/usr/sbin/nologin", "-c", "agentbox agent "+a.Name, a.User())
}

// teardown is §4.1's removal of the OS half: (live) terminate the sessions, stop user@, kill the uid; then delete the
// user, its group, its linger file and its drop-ins.
func teardown(a Agent, live bool) (changed bool, err error) {
	uid := strconv.Itoa(a.UID())
	u, lerr := user.LookupId(uid)
	if lerr == nil && u.Username != a.User() {
		return false, fmt.Errorf("accounts: uid %s belongs to %s, not the retired %s", uid, u.Username, a.User())
	}
	if lerr == nil {
		if live {
			exec.Command("loginctl", "disable-linger", a.User()).Run()
			exec.Command("loginctl", "terminate-user", a.User()).Run()
			exec.Command("systemctl", "stop", "user@"+uid+".service").Run()
			for i := 0; ; i++ {
				exec.Command("pkill", "-KILL", "-U", uid).Run()
				if exec.Command("pgrep", "-U", uid).Run() != nil {
					break
				}
				if i == 100 {
					return false, fmt.Errorf("accounts: processes of uid %s survive SIGKILL", uid)
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
		if err := run("userdel", a.User()); err != nil {
			return false, err
		}
	}
	if g, err := user.LookupGroupId(uid); err == nil && g.Name == a.User() {
		if err := run("groupdel", a.User()); err != nil {
			return false, err
		}
	}
	if err := os.Remove(lingerDir + "/" + a.User()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	for _, p := range []string{a.userDropIn(), a.sliceDropIn()} {
		if err := os.Remove(p); err == nil {
			changed = true
			os.Remove(p[:strings.LastIndexByte(p, '/')])
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	return changed, nil
}

// Reconcile applies the ids table to the box, idempotently (§3.2, §4.1). Retired agents lose their user and drop-ins,
// and their subvolumes move to the archive; active agents get their stores, user, drop-ins and linger; /etc/subuid and
// /etc/subgid are rewritten from the active rows. live is agentbox-accounts.service on a running box: removal stops
// the agent's sessions and processes, and linger goes through logind, which starts the user manager. At boot (reconcile)
// logind isn't up yet, so linger is its file.
func Reconcile(db *sql.DB, live bool) error {
	all, err := List(db)
	if err != nil {
		return err
	}
	reload := false
	active := map[string]bool{}
	for _, a := range all {
		active[a.Name] = active[a.Name] || a.Active
	}
	for _, a := range all {
		if a.Active {
			continue
		}
		ch, err := teardown(a, live)
		if err != nil {
			return err
		}
		reload = reload || ch
		if err := archive(a); err != nil {
			return err
		}
		if !active[a.Name] {
			if err := os.RemoveAll(a.XDG()); err != nil {
				return err
			}
		}
	}
	for _, a := range all {
		if !a.Active {
			continue
		}
		if err := EnsureStore(a, 0); err != nil {
			return err
		}
		if err := ensureUser(a); err != nil {
			return err
		}
		for _, f := range [][2]string{{a.userDropIn(), a.UserDropIn()}, {a.sliceDropIn(), SliceDropIn}} {
			ch, err := writeChanged(f[0], f[1])
			if err != nil {
				return err
			}
			reload = reload || ch
		}
	}
	for _, f := range SubidFiles {
		cur, err := os.ReadFile(f)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		b, err := RenderSubids(cur, all)
		if err != nil {
			return fmt.Errorf("accounts: %s: %v", f, err)
		}
		if !bytes.Equal(b, cur) {
			if err := gens.WriteAtomic(f, b, 0o644); err != nil {
				return err
			}
		}
	}
	if reload {
		if err := run("systemctl", "daemon-reload"); err != nil {
			return err
		}
	}
	for _, a := range all {
		if !a.Active {
			continue
		}
		if live {
			if err := run("loginctl", "enable-linger", a.User()); err != nil {
				return err
			}
		} else if err := writeIfChanged(lingerDir+"/"+a.User(), ""); err != nil {
			return err
		}
	}
	return nil
}
