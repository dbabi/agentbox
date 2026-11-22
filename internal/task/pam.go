package task

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// PAMLogin is /etc/pam.d/login: each task launch opens one PAM login session for the agent (the -M ag-<name>@ bridge).
const PAMLogin = "/etc/pam.d/login"

const skipMark = "pam_succeed_if.so quiet user =~ ag-*"

var motdLine = regexp.MustCompile(`^session\s+\S+\s+pam_motd\.so(\s|$)`)

// SkipMotd returns login with the agent line right before its adjacent pam_motd lines (Appendix C), so a task launch
// never runs /etc/update-motd.d/* while humans still get motd. It drops any earlier copy of the line first, so a rerun
// changes nothing, and the skip count is the number of adjacent pam_motd lines.
func SkipMotd(login string) (string, error) {
	var keep []string
	for _, l := range strings.Split(login, "\n") {
		if !strings.Contains(l, skipMark) {
			keep = append(keep, l)
		}
	}
	at, n := -1, 0
	for i, l := range keep {
		if motdLine.MatchString(l) {
			if at < 0 {
				at = i
			} else if i != at+n {
				return "", fmt.Errorf("the pam_motd lines are not adjacent")
			}
			n++
		}
	}
	if at < 0 {
		return login, nil // no motd for anyone: nothing to skip
	}
	line := fmt.Sprintf("session [success=%d default=ignore] %s", n, skipMark)
	out := append(append(append([]string{}, keep[:at]...), line), keep[at:]...)
	return strings.Join(out, "\n"), nil
}

// EnsureSkipMotd applies SkipMotd to path; reconcile runs it at every boot, since dpkg keeps the local version.
func EnsureSkipMotd(path string) error {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	out, err := SkipMotd(string(b))
	if err != nil || out == string(b) {
		return err
	}
	t := path + ".agentbox-new"
	if err := os.WriteFile(t, []byte(out), 0o644); err != nil {
		return err
	}
	return os.Rename(t, path)
}
