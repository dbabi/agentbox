package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestSyncBeforeRename runs install.sh under dash with fake id, dpkg, systemctl, sync and mv, and the box's paths moved
// into a temp dir. btrfs can commit the release dir's rename before the staged files' data, and every rerun refuses a
// release dir with other content, so a sync must come right before that rename. The last sync covers the links and the
// unit copies, since firstboot marks itself done next.
func TestSyncBeforeRename(t *testing.T) {
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
	for _, p := range []string{"A=/var/lib/agentbox\n", "ETC=/etc\n"} {
		if strings.Count(s, p) != 1 {
			t.Fatalf("install.sh: want %q once, or the run below writes to the real path", p)
		}
	}
	if strings.Count(s, "/etc/") != 0 {
		t.Fatal("install.sh: every /etc path must go through $ETC, or the run below writes to the real one")
	}
	s = strings.NewReplacer("A=/var/lib/agentbox\n", "A="+box+"/var/lib/agentbox\n", "ETC=/etc\n", "ETC="+box+"/etc\n").Replace(s)
	for name, body := range map[string]string{"install.sh": s, "bin/linux-arm64/agentbox": "#!/bin/sh\necho 1.0.0\n",
		"systemd/agentbox-x.service": "[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n",
		"sysusers.d/agentbox.conf":   "u agentbox -\n"} {
		os.MkdirAll(filepath.Dir(filepath.Join(rel, name)), 0o755)
		os.WriteFile(filepath.Join(rel, name), []byte(body), 0o755)
	}
	os.MkdirAll(filepath.Join(box, "etc/systemd/system"), 0o755)
	for name, body := range map[string]string{"id": "echo 0", "dpkg": "echo arm64", "systemctl": ":", "sync": `echo sync >> "$TRACE"`,
		"systemd-sysusers": ":", "getent": ":", "apt-get": "exit 1",
		// GNU mv -T renames onto the link itself; dropping the link first does the same with BSD mv
		"mv": `echo "mv $*" >> "$TRACE"; [ "$1" != -T ] || { shift; rm -f "$2"; }; exec "` + mv + `" "$@"`} {
		os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755)
	}
	trace := filepath.Join(box, "trace")
	c := exec.Command(dash, filepath.Join(rel, "install.sh"), "--from-firstboot")
	c.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TRACE="+trace)
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("install.sh: %v\n%s", err, out)
	}
	b, _ := os.ReadFile(trace)
	got := strings.Split(strings.TrimSpace(string(b)), "\n")
	r := box + "/var/lib/agentbox/releases/"
	if i := slices.Index(got, "mv "+r+".1.0.0.new "+r+"1.0.0"); i < 1 || got[i-1] != "sync" || got[len(got)-1] != "sync" {
		t.Errorf("want a sync right before the release dir's rename, and a sync last; got:\n%s", b)
	}
}
