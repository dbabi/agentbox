// Package ntfy configures Ubuntu's packaged ntfy for agentbox (ARCHITECTURE.md §2 "ntfy (packaged)", §2.1, §6.1):
// no TCP listener, a setgid Unix socket dir for the agentbox-notify group, deny-all topic ACLs, the firewall drop-in,
// and fwcheck's assertion on the unit's identity. rootd fills ntfy_dst4/6 and fw.Check holds them to rootd.db.
package ntfy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"agentbox/internal/fw"
	"agentbox/internal/rootd/gens"
	"agentbox/internal/sockets"
)

const (
	Unit         = "ntfy.service"
	User         = "_ntfy"           // the package's sysusers entry; agentbox never creates an ntfy user (§12)
	Group        = "agentbox-notify" // the socket dir's group: agentbox, rootd and the ntfy-tcp proxy (§2.1)
	NotifyUser   = "agentbox-notify" // the ntfy ACL identity that publishes, write-only to Topics
	Topics       = "agentbox-*"
	ConfigPath   = "/etc/ntfy/server.yml"
	DropInPath   = "/etc/systemd/system/ntfy.service.d/50-agentbox.conf"
	TmpfilesPath = sockets.NtfyTmpfiles
	Socket       = "/run/ntfy/ntfy.sock"
	TokenPath    = "/var/lib/agentbox/control/ntfy/notify.token"
	authFile     = "/var/lib/ntfy/user.db"
	agentboxBin  = "/var/lib/agentbox/current/bin/agentbox"
)

// ServerYML is /etc/ntfy/server.yml. listen-http "-" turns off ntfy's default :80 on every interface; deny-all needs
// auth-file to mean anything; upstream-base-url (the iOS push relay, which gets only SHA-256(base-url/topic) and the
// message id) needs base-url, or ntfy refuses to start.
func ServerYML(baseURL string) string {
	return `# Written by agentbox-reconcile (ARCHITECTURE.md §2); local edits are replaced at the next boot.
base-url: "` + baseURL + `"
listen-http: "-"
listen-unix: ` + Socket + `
listen-unix-mode: 0660
cache-file: /var/lib/ntfy/cache.db
auth-file: ` + authFile + `
auth-default-access: deny-all
upstream-base-url: "https://ntfy.sh"
`
}

// BaseURL is the tailscale serve URL that fronts 127.0.0.1:43200 (§5.4 Origin isolation: ntfy on --https=8443).
// shortcut: the box's hostname stands in for <box>.<tailnet>.ts.net until rootd writes the serve config (weeks 9-10);
// only the iOS push upstream hash depends on it.
func BaseURL(host string) string { return "https://" + host + ":8443" }

// tmpfiles: the ntfy dirs of the socket inventory (§2.1); the setgid /run/ntfy gives the socket its group.
var tmpfiles = "# Written by agentbox-reconcile (ARCHITECTURE.md §2).\n" + sockets.TmpfilesLines(sockets.Inventory(), sockets.NtfyTmpfiles)

// dropIn: the packaged unit orders only After=network.target, so without it ntfy starts outside the firewall gate.
// It starts after rootd's READY=1 too, which waits for the refill its fwcheck compares (§6.1, #220).
const dropIn = `# Written by agentbox-reconcile (ARCHITECTURE.md §2).
[Unit]
Requires=agentbox-firewall.service agentbox-rootd.service
After=agentbox-firewall.service agentbox-rootd.service

[Service]
ExecStartPre=+` + agentboxBin + ` fwcheck
`

func run(name string, args ...string) ([]byte, error) {
	var stderr bytes.Buffer
	c := exec.Command(name, args...)
	c.Env = append(os.Environ(), "LC_ALL=C")
	c.Stderr = &stderr
	out, err := c.Output()
	if err != nil {
		return out, fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, bytes.TrimSpace(stderr.Bytes()))
	}
	return out, nil
}

// writeIfChanged writes p root-owned with mode, atomically, and reports whether the content changed.
func writeIfChanged(p, content string, mode os.FileMode) (bool, error) {
	if b, err := os.ReadFile(p); err == nil && string(b) == content {
		if fi, err := os.Stat(p); err == nil && fi.Mode().Perm() == mode {
			return false, os.Lchown(p, 0, 0)
		}
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return false, err
	}
	if err := gens.WriteAtomic(p, []byte(content), mode); err != nil {
		return false, err
	}
	return true, os.Lchown(p, 0, 0)
}

// Setup is the §2 install order, run by agentbox-reconcile on every boot after install.sh put the package in:
// _ntfy exists → write the files → systemd-tmpfiles --create → the ruleset parses → ACLs → enable ntfy.service.
// Any failure stops reconcile, so every agentbox unit stays down.
func Setup() error {
	if _, err := user.Lookup(User); err != nil {
		return fmt.Errorf("ntfy: no %s user (is the ntfy package installed?): %v", User, err)
	}
	if _, err := user.LookupGroup(Group); err != nil {
		if _, err := run("groupadd", "--system", Group); err != nil {
			return err
		}
	}
	host, err := os.Hostname()
	if err != nil {
		return err
	}
	reload := false
	for _, f := range []struct {
		p, c string
	}{{ConfigPath, ServerYML(BaseURL(host))}, {TmpfilesPath, tmpfiles}, {DropInPath, dropIn}} {
		ch, err := writeIfChanged(f.p, f.c, 0o644)
		if err != nil {
			return fmt.Errorf("ntfy: %s: %v", f.p, err)
		}
		reload = reload || ch && strings.HasPrefix(f.p, "/etc/systemd/")
	}
	if reload {
		if _, err := run("systemctl", "daemon-reload"); err != nil {
			return err
		}
	}
	if _, err := run("systemd-tmpfiles", "--create", TmpfilesPath); err != nil {
		return err
	}
	if err := fw.WriteConfig(); err != nil { // the ruleset names _ntfy: it must parse before ntfy is enabled
		return err
	}
	if err := setupACL(); err != nil {
		return err
	}
	_, err = run("systemctl", "enable", Unit)
	return err
}

// ntfyCLI runs the ntfy CLI as _ntfy, so user.db stays owned by the uid that serves it.
func ntfyCLI(env []string, args ...string) ([]byte, error) {
	return ntfyRun(append([]string{"env"}, append(env, append([]string{"ntfy"}, args...)...)...)...)
}

func ntfyRun(args ...string) ([]byte, error) {
	var stderr bytes.Buffer
	c := exec.Command("runuser", append([]string{"-u", User, "--"}, args...)...)
	c.Env = append(os.Environ(), "LC_ALL=C")
	c.Stderr = &stderr
	c.Dir = "/"
	out, err := c.Output()
	if err != nil {
		return out, fmt.Errorf("%s: %v: %s", strings.Join(args, " "), err, bytes.TrimSpace(stderr.Bytes()))
	}
	return append(out, stderr.Bytes()...), nil
}

var tokenRE = regexp.MustCompile(`\btk_[0-9A-Za-z]{29}\b`)

// setupACL gives NotifyUser write-only access to Topics and nothing else (deny-all covers everyone else), and keeps
// one access token for it in TokenPath (root-only; agentbox-notify publishes with it over the socket).
func setupACL() error {
	// the CLI refuses a missing auth-file ("start the server at least once"); an empty one gets the schema. ntfy
	// must not serve before its ACLs exist, so create it here.
	if _, err := os.Stat(authFile); errors.Is(err, os.ErrNotExist) {
		if _, err := ntfyRun("touch", authFile); err != nil {
			return err
		}
	}
	cfg := "--config=" + ConfigPath
	out, err := ntfyCLI(nil, "user", cfg, "list")
	if err != nil {
		return err
	}
	if !regexp.MustCompile(`(?m)^user ` + regexp.QuoteMeta(NotifyUser) + ` `).Match(out) {
		// tokens authenticate; the password is never used, so it is random and never stored
		pw := make([]byte, 24)
		f, err := os.Open("/dev/urandom")
		if err != nil {
			return err
		}
		_, err = f.Read(pw)
		f.Close()
		if err != nil {
			return err
		}
		if _, err := ntfyCLI([]string{fmt.Sprintf("NTFY_PASSWORD=%x", pw)}, "user", cfg, "add", "--role=user", NotifyUser); err != nil {
			return err
		}
	}
	if _, err := ntfyCLI(nil, "access", cfg, NotifyUser, Topics, "write-only"); err != nil {
		return err
	}
	tok, _ := os.ReadFile(TokenPath)
	list, err := ntfyCLI(nil, "token", cfg, "list", NotifyUser)
	if err != nil && !strings.Contains(err.Error(), "no tokens") {
		return err
	}
	if t := strings.TrimSpace(string(tok)); t != "" && tokenRE.MatchString(t) && strings.Contains(string(list), t) {
		return nil
	}
	out, err = ntfyCLI(nil, "token", cfg, "add", NotifyUser)
	if err != nil {
		return err
	}
	t := tokenRE.Find(out)
	if t == nil {
		return fmt.Errorf("ntfy token add printed no token: %q", out)
	}
	if err := os.MkdirAll(filepath.Dir(TokenPath), 0o700); err != nil {
		return err
	}
	_, err = writeIfChanged(TokenPath, string(t)+"\n", 0o600)
	return err
}

// CheckUser is fwcheck's ntfy assertion (§6.1): the unit runs as _ntfy, the uid the ruleset names, and a running
// ntfy has exactly that uid. Anything else fails closed, so a packaging change can't leave ntfy unconfined.
func CheckUser() error {
	out, err := run("systemctl", "show", "-P", "User", Unit)
	if err != nil {
		return err
	}
	if u := strings.TrimSpace(string(out)); u != User {
		return fmt.Errorf("fwcheck: %s runs as user %q, not %s", Unit, u, User)
	}
	u, err := user.Lookup(User)
	if err != nil {
		return fmt.Errorf("fwcheck: %v", err)
	}
	out, err = run("systemctl", "show", "-P", "MainPID", Unit)
	if err != nil {
		return err
	}
	pid := strings.TrimSpace(string(out))
	if pid == "0" || pid == "" {
		return nil
	}
	return settleUID(func() (string, error) {
		st, err := os.ReadFile("/proc/" + pid + "/status")
		return string(st), err
	}, u.Uid, 10, 100*time.Millisecond)
}

// settleUID checks one process's uids, again up to tries times: systemd forks ntfy as root and drops to _ntfy just
// before exec, so a check in that window must wait (#84). A process that stays on another uid still fails.
func settleUID(status func() (string, error), uid string, tries int, wait time.Duration) error {
	for i := 0; ; i++ {
		st, err := status()
		if errors.Is(err, os.ErrNotExist) {
			return nil // exited since systemctl show
		}
		if err != nil {
			return err
		}
		err = checkStatusUID(st, uid)
		if err == nil || i >= tries {
			return err
		}
		time.Sleep(wait)
	}
}

// checkStatusUID checks the real, effective, saved and fs uids of /proc/<pid>/status.
func checkStatusUID(status, uid string) error {
	for _, l := range strings.Split(status, "\n") {
		if f := strings.Fields(l); len(f) == 5 && f[0] == "Uid:" {
			for _, v := range f[1:] {
				if v != uid {
					return fmt.Errorf("fwcheck: %s is running with uids %s, not %s (%s)", Unit, strings.Join(f[1:], " "), uid, User)
				}
			}
			return nil
		}
	}
	return errors.New("fwcheck: no Uid line in ntfy's /proc status")
}

// AlertTopic is where box alerts go (§4.2's token-scan hit, and later alerts).
const AlertTopic = "agentbox-alerts"

// Publish posts one message to topic on ntfy's Unix socket with NotifyUser's token. The caller must reach the socket
// (root, or the agentbox-notify group).
func Publish(sock, tokenPath, topic, title, msg string) error {
	tok, err := os.ReadFile(tokenPath)
	if err != nil {
		return err
	}
	// no keep-alive: this Transport is dropped after one request, and an idle connection in it would never close
	// (rootd's outbox retries every 10 s)
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}}}
	req, err := http.NewRequest(http.MethodPost, "http://ntfy/"+topic, strings.NewReader(msg))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	req.Header.Set("Title", title)
	req.Header.Set("Priority", "high")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("ntfy publish: %s: %s", resp.Status, bytes.TrimSpace(b))
	}
	return nil
}
