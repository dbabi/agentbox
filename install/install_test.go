package install

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// stage writes install.sh into a temp release with the box's paths moved into box, and puts fake id, dpkg, systemctl,
// sync, mv and the rest first on PATH; stubs adds or replaces fakes. Every fake sees TRACE and BOX. The command runs
// install.sh under dash.
func stage(t *testing.T, stubs map[string]string) (c *exec.Cmd, box, trace string) {
	t.Helper()
	dash, err := exec.LookPath("dash")
	if err != nil {
		t.Skip("dash not installed")
	}
	mv, err := exec.LookPath("mv")
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	box, bin, rel := t.TempDir(), t.TempDir(), t.TempDir()
	s := string(src)
	for _, p := range []string{"A=/var/lib/agentbox\n", "ETC=/etc\n", "L=/usr/lib\n", "RCD=/usr/sbin/policy-rc.d\n"} {
		if strings.Count(s, p) != 1 {
			t.Fatalf("install.sh: want %q once, or the run below writes to the real path", p)
		}
	}
	if strings.Count(s, "/etc/") != 0 || strings.Count(s, "/usr/lib/") != 0 || strings.Count(s, "/usr/sbin/") != 1 {
		t.Fatal("install.sh: every /etc, /usr/lib and /usr/sbin path must go through $ETC, $L and $RCD, or the run below writes to the real one")
	}
	s = strings.NewReplacer("A=/var/lib/agentbox\n", "A="+box+"/var/lib/agentbox\n", "ETC=/etc\n", "ETC="+box+"/etc\n",
		"L=/usr/lib\n", "L="+box+"/usr/lib\n", "RCD=/usr/sbin/policy-rc.d\n", "RCD="+box+"/policy-rc.d\n").Replace(s)
	for name, body := range map[string]string{"install.sh": s, "bin/linux-arm64/agentbox": "#!/bin/sh\necho 1.0.0\n",
		"systemd/agentbox-x.service": "[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n",
		"sysusers.d/agentbox.conf":   "u agentbox-x -\n", "tmpfiles.d/agentbox.conf": "d /run/agentbox-x 0711 root root -\n",
		"gen/cedar.schema": "namespace Agentbox {}\n", "seccomp/seccomp-task.json": "{}\n", "git-hooks/pre-receive": "#!/bin/sh\n",
		"image/linux-arm64/task.oci.tar": "oci\n", "SHA256SUMS": "x  image/linux-arm64/task.oci.tar\n"} {
		os.MkdirAll(filepath.Dir(filepath.Join(rel, name)), 0o755)
		os.WriteFile(filepath.Join(rel, name), []byte(body), 0o755)
	}
	for _, d := range []string{"etc/systemd/system", "usr/lib/sysusers.d", "usr/lib/tmpfiles.d"} {
		os.MkdirAll(filepath.Join(box, d), 0o755)
	}
	fakes := map[string]string{"id": "echo 0", "dpkg": `[ "$1" = -s ] && echo "Status: install ok installed" || echo arm64`, "systemctl": ":", "sync": `echo sync >> "$TRACE"`,
		"systemd-sysusers": `echo "sysusers $*" >> "$TRACE"`, "systemd-tmpfiles": `echo "tmpfiles $*" >> "$TRACE"`,
		"systemd-creds": `echo "creds $*" >> "$TRACE"`,
		"getent":        ":", "apt-get": "exit 1",
		// GNU mv -T renames onto the link itself; dropping the link first does the same with BSD mv
		"mv": `echo "mv $*" >> "$TRACE"; [ "$1" != -T ] || { shift; rm -f "$2"; }; exec "` + mv + `" "$@"`}
	for name, body := range stubs {
		fakes[name] = body
	}
	for name, body := range fakes {
		os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755)
	}
	trace = filepath.Join(box, "trace")
	c = exec.Command(dash, filepath.Join(rel, "install.sh"), "--from-firstboot")
	c.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TRACE="+trace, "BOX="+box)
	return c, box, trace
}

// TestSyncBeforeRename runs install.sh with the fakes of stage. btrfs can commit the release dir's rename before the
// staged files' data, and every rerun refuses a release dir with other content, so a sync must come right before that
// rename. The last sync covers the links and the unit copies, since firstboot marks itself done next.
func TestSyncBeforeRename(t *testing.T) {
	c, box, trace := stage(t, nil)
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("install.sh: %v\n%s", err, out)
	}
	b, _ := os.ReadFile(trace)
	got := strings.Split(strings.TrimSpace(string(b)), "\n")
	r := box + "/var/lib/agentbox/releases/"
	if i := slices.Index(got, "mv "+r+".1.0.0.new "+r+"1.0.0"); i < 1 || got[i-1] != "sync" || got[len(got)-1] != "sync" {
		t.Errorf("want a sync right before the release dir's rename, and a sync last; got:\n%s", b)
	}
	// the users and dirs the units name exist before systemctl enable; the copies are the release's
	if !slices.Contains(got, "sysusers "+box+"/usr/lib/sysusers.d/agentbox.conf") || !slices.Contains(got, "tmpfiles --create "+box+"/usr/lib/tmpfiles.d/agentbox.conf") {
		t.Errorf("want systemd-sysusers and systemd-tmpfiles --create on the installed copies; got:\n%s", b)
	}
	if !slices.Contains(got, "creds setup") { // #108: the host key rootd encrypts the brokers' credentials with in none mode
		t.Errorf("want systemd-creds setup; got:\n%s", b)
	}
	if c, err := os.ReadFile(filepath.Join(box, "usr/lib/sysusers.d/agentbox.conf")); err != nil || string(c) != "u agentbox-x -\n" {
		t.Errorf("sysusers copy: %q %v", c, err)
	}
	// the box's task image and the SHA256SUMS rootd checks it against (#102); podman auto-update masked (#109)
	if c, err := os.ReadFile(r + "1.0.0/image/task.oci.tar"); err != nil || string(c) != "oci\n" {
		t.Errorf("task image: %q %v", c, err)
	}
	if _, err := os.Stat(r + "1.0.0/SHA256SUMS"); err != nil {
		t.Error(err)
	}
	for _, u := range []string{"podman-auto-update.timer", "podman-auto-update.service"} {
		if l, err := os.Readlink(filepath.Join(box, "etc/systemd/user", u)); err != nil || l != "/dev/null" {
			t.Errorf("%s: %q %v, want masked", u, l, err)
		}
	}
}

// TestPolicyRCD: a policy-rc.d with install.sh's own bytes is one that a killed run left, so install.sh removes it,
// even with nothing to install. Any other one stops the apt step. During that step install.sh's own is in place, dpkg
// first configures what an earlier run unpacked, and a TERM, which systemd sends at a stop, still removes it (#218).
func TestPolicyRCD(t *testing.T) {
	own := "#!/bin/sh\n# agentbox install.sh: no service starts during its apt step\nexit 101\n"
	foreign := "#!/bin/sh\nexit 101\n"
	noNtfy := `case $1 in -s) [ "$2" = ntfy ] || echo "Status: install ok installed" ;; --configure) echo "dpkg $*" >> "$TRACE" ;; *) echo arm64 ;; esac`
	apt := `cmp -s "$BOX/policy-rc.d" "$BOX/own" && echo "apt-get $*" >> "$TRACE"` // fails unless install.sh's own is in place
	for _, tc := range []struct {
		name, dpkg, rcd string
		ok              bool
		trace           []string
	}{
		{"its own left behind, nothing to install", "", own, true, nil},
		{"its own left behind, ntfy to install", noNtfy, own, true,
			[]string{"dpkg --configure -a", "apt-get -q -y -o DPkg::Lock::Timeout=300 --no-install-recommends install ntfy"}},
		{"another one, nothing to install", "", foreign, true, nil},
		{"another one, ntfy to install", noNtfy, foreign, false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubs := map[string]string{"apt-get": apt}
			if tc.dpkg != "" {
				stubs["dpkg"] = tc.dpkg
			}
			c, box, trace := stage(t, stubs)
			rcd := filepath.Join(box, "policy-rc.d")
			os.WriteFile(filepath.Join(box, "own"), []byte(own), 0o644)
			os.WriteFile(rcd, []byte(tc.rcd), 0o755)
			out, err := c.CombinedOutput()
			if (err == nil) != tc.ok || !tc.ok && !strings.Contains(string(out), rcd+" exists; remove it and rerun") {
				t.Fatalf("install.sh: %v\n%s", err, out)
			}
			b, _ := os.ReadFile(trace)
			var got []string
			for _, l := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(l, "dpkg ") || strings.HasPrefix(l, "apt-get ") {
					got = append(got, l)
				}
			}
			if !slices.Equal(got, tc.trace) {
				t.Errorf("dpkg and apt-get calls: got %q, want %q", got, tc.trace)
			}
			left, err := os.ReadFile(rcd)
			if tc.rcd == own && !errors.Is(err, os.ErrNotExist) || tc.rcd == foreign && string(left) != foreign {
				t.Errorf("policy-rc.d after the run: %q %v", left, err)
			}
		})
	}
	t.Run("TERM during the apt step", func(t *testing.T) {
		c, box, _ := stage(t, map[string]string{"dpkg": noNtfy, "apt-get": `touch "$BOX/apt"; exec sleep 30`})
		c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		for i := 0; ; i++ {
			if _, err := os.Stat(filepath.Join(box, "apt")); err == nil {
				break
			}
			if i == 200 {
				c.Process.Kill()
				t.Fatal("apt-get never ran")
			}
			time.Sleep(50 * time.Millisecond)
		}
		if _, err := os.Stat(filepath.Join(box, "policy-rc.d")); err != nil {
			t.Errorf("no policy-rc.d during the apt step: %v", err)
		}
		syscall.Kill(-c.Process.Pid, syscall.SIGTERM) // the whole group, as systemd's stop does
		if err := c.Wait(); err == nil {
			t.Error("install.sh exited 0 after a TERM")
		}
		if _, err := os.Stat(filepath.Join(box, "policy-rc.d")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("policy-rc.d left after a TERM: %v", err)
		}
	})
}
