package rootd

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"agentbox/internal/task"
)

// Agent ids (§4.1): agent N is ag-<name> with uid and gid 70000+N and the sub-id block 0x70000000+N·0x10000.
const (
	AgentUIDBase = 70000
	SubIDBase    = 0x70000000
	SubIDSize    = 0x10000
)

func AgentUID(n int) int   { return AgentUIDBase + n }
func AgentSubID(n int) int { return SubIDBase + n*SubIDSize }

// Account paths (§4.1, Appendix C).
func WorkspaceDir(agent string) string { return "/var/lib/agentbox/data/workspaces/" + agent }
func StorageDir(agent string) string   { return "/var/lib/agentbox/data/agents/" + agent + "/storage" }
func XDG(agent string) string          { return task.ControlDir + "/xdg/" + agent }
func HomeDir(agent string) string      { return task.ControlDir + "/home/" + agent }

// UserDropIn is Appendix C's user@<uid>.service drop-in: the user manager starts only after the firewall, reconcile
// and rootd, with fwcheck passing, and with root-owned XDG dirs, so podman reads only rootd's storage.conf.
func UserDropIn(agent string) string {
	x := XDG(agent)
	return "# agentbox (ARCHITECTURE.md §4.1, Appendix C)\n[Unit]\nRequires=agentbox-firewall.service agentbox-reconcile.service agentbox-rootd.service\n" +
		"After=agentbox-firewall.service agentbox-reconcile.service agentbox-rootd.service\n[Service]\n" +
		"Environment=XDG_CONFIG_HOME=" + x + "/config XDG_DATA_HOME=" + x + "/data\nExecStartPre=+" + task.Binary + " fwcheck\n"
}

// SliceDropIn is the agent's user-<uid>.slice limits (Appendix C).
const SliceDropIn = "# agentbox (ARCHITECTURE.md Appendix C)\n[Slice]\nCPUWeight=100\nMemoryHigh=6G\nMemoryMax=8G\nTasksMax=4096\nIOWeight=100\n"

// StorageConf points the agent's rootless podman at its own storage (Appendix C).
func StorageConf(agent string, uid int) string {
	return "[storage]\ndriver = \"overlay\"\ngraphroot = \"" + StorageDir(agent) + "\"\nrunroot = \"/run/user/" + strconv.Itoa(uid) + "/containers\"\n"
}

// StubAdd makes agent's account the way rootd's agent.add will (§4.1), run by root from the admin shell.
//
// shortcut: the accounts area (#12) replaces this with rootd's agent.add: the ids table allocates N (here: the next uid
// after the highest ag-* uid, so a removed agent's uid can come back), the workspace and storage become subvolumes in
// qgroup 1/N, and reconcile re-applies the files below at boot.
func StubAdd(agent string) error {
	if !agentRe.MatchString(agent) {
		return fmt.Errorf("bad agent name %q", agent)
	}
	uid := 0
	if u, err := user.Lookup("ag-" + agent); err == nil {
		uid, _ = strconv.Atoi(u.Uid)
	} else {
		n, err := nextAgentN()
		if err != nil {
			return err
		}
		uid = AgentUID(n)
		sub := AgentSubID(n)
		if err := run("useradd", "--system", "-M", "-d", HomeDir(agent), "-s", "/usr/sbin/nologin", "-u", strconv.Itoa(uid), "-U", "ag-"+agent); err != nil {
			return err
		}
		r := fmt.Sprintf("%d-%d", sub, sub+SubIDSize-1)
		if err := run("usermod", "--add-subuids", r, "--add-subgids", r, "ag-"+agent); err != nil {
			return err
		}
	}
	x := XDG(agent)
	for _, d := range []struct {
		p    string
		mode os.FileMode
		own  bool
	}{{task.ControlDir, 0o711, false}, {filepath.Dir(HomeDir(agent)), 0o711, false}, {HomeDir(agent), 0o755, false},
		{filepath.Dir(x), 0o711, false}, {x, 0o755, false}, {x + "/config/containers", 0o755, false}, {x + "/data", 0o755, false},
		{filepath.Dir(WorkspaceDir(agent)), 0o711, false}, {WorkspaceDir(agent), 0o700, true},
		{filepath.Dir(filepath.Dir(StorageDir(agent))), 0o711, false}, {filepath.Dir(StorageDir(agent)), 0o711, false},
		// 0711: with --userns=keep-id, crun opens the layers as the container root, an unmapped sub-id, which must traverse it
		{StorageDir(agent), 0o711, true}} {
		if err := os.MkdirAll(d.p, d.mode); err != nil {
			return err
		}
		if err := os.Chmod(d.p, d.mode); err != nil {
			return err
		}
		o := 0
		if d.own {
			o = uid
		}
		if err := os.Lchown(d.p, o, o); err != nil {
			return err
		}
	}
	files := map[string]string{
		x + "/config/containers/storage.conf":                                      StorageConf(agent, uid),
		fmt.Sprintf("/etc/systemd/system/user@%d.service.d/50-agentbox.conf", uid): UserDropIn(agent),
		fmt.Sprintf("/etc/systemd/system/user-%d.slice.d/50-agentbox.conf", uid):   SliceDropIn,
	}
	for p, c := range files {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
			return err
		}
	}
	if err := os.WriteFile(task.ImageTar, task.Skeleton(), 0o644); err != nil {
		return err
	}
	if err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := run("loginctl", "enable-linger", "ag-"+agent); err != nil {
		return err
	}
	// the image is loaded per agent user (§4.2), through the user manager so podman's pause process lands there
	return run("systemd-run", "--user", "-M", "ag-"+agent+"@", "--wait", "--quiet", "--collect",
		task.Podman, "import", task.ImageTar, task.Image())
}

func nextAgentN() (int, error) {
	b, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return 0, err
	}
	n := 0
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Split(l, ":")
		if len(f) > 2 && strings.HasPrefix(f[0], "ag-") {
			if u, err := strconv.Atoi(f[2]); err == nil && u > AgentUIDBase && u-AgentUIDBase > n {
				n = u - AgentUIDBase
			}
		}
	}
	if n >= 999 {
		return 0, fmt.Errorf("no agent id left")
	}
	return n + 1, nil
}

func run(argv ...string) error {
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %v: %s", strings.Join(argv, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
