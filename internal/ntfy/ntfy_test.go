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
