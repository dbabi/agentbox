package task

import (
	"strings"
	"testing"
)

const ubuntuLogin = `auth       optional   pam_faildelay.so  delay=3000000
session    required     pam_env.so readenv=1
# Prints the message of the day upon successful login.
session    optional   pam_motd.so motd=/run/motd.dynamic
session    optional   pam_motd.so noupdate
session    optional   pam_mail.so standard
@include common-session
`

func TestSkipMotd(t *testing.T) {
	out, err := SkipMotd(ubuntuLogin)
	if err != nil {
		t.Fatal(err)
	}
	l := strings.Split(out, "\n")
	if l[3] != "session [success=2 default=ignore] pam_succeed_if.so quiet user =~ ag-*" || !strings.Contains(l[4], "motd=/run/motd.dynamic") {
		t.Fatalf("got:\n%s", out)
	}
	again, _ := SkipMotd(out)
	if again != out {
		t.Fatalf("not idempotent:\n%s", again)
	}
	moved := strings.Replace(out, l[3]+"\n", "", 1) + l[3] + "\n"
	if fixed, _ := SkipMotd(moved); fixed != out {
		t.Fatalf("a misplaced line must move back:\n%s", fixed)
	}
	if _, err := SkipMotd("session optional pam_motd.so a\nsession optional pam_env.so\nsession optional pam_motd.so b\n"); err == nil {
		t.Fatal("non-adjacent pam_motd lines must be an error")
	}
}
