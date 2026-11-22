package ntfy

import (
	"strings"
	"testing"
)

func TestServerYML(t *testing.T) {
	y := ServerYML(BaseURL("box"))
	for _, l := range []string{`base-url: "https://box:8443"`, `listen-http: "-"`, "listen-unix: /run/ntfy/ntfy.sock",
		"listen-unix-mode: 0660", "auth-file: /var/lib/ntfy/user.db", "auth-default-access: deny-all", `upstream-base-url: "https://ntfy.sh"`} {
		if !strings.Contains("\n"+y, "\n"+l+"\n") {
			t.Errorf("server.yml has no line %q", l)
		}
	}
	if !strings.Contains(dropIn, "Requires=agentbox-firewall.service\n") || !strings.Contains(dropIn, "ExecStartPre=+"+agentboxBin+" fwcheck\n") {
		t.Error("drop-in lost the firewall gate")
	}
	if !strings.Contains(tmpfiles, "d /run/ntfy 2750 _ntfy agentbox-notify -\n") {
		t.Error("tmpfiles lost the setgid socket dir")
	}
}

func TestCheckStatusUID(t *testing.T) {
	st := "Name:\tntfy\nUid:\t983\t983\t983\t983\nGid:\t983\t983\t983\t983\n"
	if err := checkStatusUID(st, "983"); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{strings.Replace(st, "983\t983\t983\t983\nGid", "983\t0\t983\t983\nGid", 1), "Name:\tntfy\n"} {
		if checkStatusUID(bad, "983") == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if checkStatusUID(st, "65534") == nil {
		t.Error("accepted another uid")
	}
}

// #84: ntfy between fork and setuid passes once it drops to _ntfy; one that stays root fails.
func TestSettleUID(t *testing.T) {
	root, ntfy := "Uid:\t0\t0\t0\t0\n", "Uid:\t972\t972\t972\t972\n"
	n := 0
	seq := func() (string, error) {
		if n++; n < 3 {
			return root, nil
		}
		return ntfy, nil
	}
	if err := settleUID(seq, "972", 10, 0); err != nil {
		t.Errorf("dropped to _ntfy on the third read: %v", err)
	}
	if err := settleUID(func() (string, error) { return root, nil }, "972", 10, 0); err == nil {
		t.Error("a process that stays root passed")
	}
}
