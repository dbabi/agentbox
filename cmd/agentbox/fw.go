package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"agentbox/internal/fw"
	"agentbox/internal/ntfy"
	"agentbox/internal/rootd"
)

// cmdFW runs `agentbox fw load|check` and `agentbox fwcheck` as root on the box (ARCHITECTURE.md §6.1).
func cmdFW(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("fw: expected load or check\n%s", usage)
	}
	fs := flag.NewFlagSet("fw "+args[0], flag.ContinueOnError)
	switch args[0] {
	case "load":
		only := fs.Bool("c", false, "write the ruleset and sysctl files and nft -c them; load nothing (install.sh)")
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		if *only {
			return fw.WriteConfig()
		}
		return fw.Load()
	case "check":
		return cmdFWCheck(args[1:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return flag.ErrHelp
	}
	return fmt.Errorf("fw: unknown subcommand %q", args[0])
}

// cmdFWCheck is fwcheck: every ExecStartPre=+ of a unit that needs the firewall, and agentbox-health.service with
// --repair, which alerts and restarts agentbox-firewall.service (Requires= restarts rootd, the brokers and the agents),
// then starts the units that an earlier failed load stopped.
func cmdFWCheck(args []string) error {
	fs := flag.NewFlagSet("fwcheck", flag.ContinueOnError)
	repair := fs.Bool("repair", false, "on a mismatch or a failed agentbox-firewall.service: alert, restart it, start the units that need it, check again")
	if err := parse(fs, args); err != nil {
		return err
	}
	bad, err := fwCheck()
	if *repair {
		// a failed load stopped every unit that Requires= the firewall; a table that checks out would leave them down (#218)
		if _, e := systemctl("is-failed", "--quiet", "agentbox-firewall.service"); e == nil {
			bad = append(bad, "agentbox-firewall.service failed")
		}
	}
	if err == nil && len(bad) == 0 {
		if *repair {
			alertClear("firewall")
		}
		return nil
	}
	if err != nil {
		bad = append(bad, err.Error())
	}
	if !*repair {
		return errors.New("fwcheck: " + strings.Join(bad, "; "))
	}
	fmt.Fprintf(os.Stderr, "agentbox: ALERT: firewall altered: %s; restarting agentbox-firewall.service\n", strings.Join(bad, "; "))
	// before the restart, which restarts ntfy too (Requires=)
	alert("firewall", "agentbox: firewall", "the firewall was altered at runtime: fwcheck restarts it, and with it rootd, the brokers and the agents, which kills running tasks")
	if out, err := systemctl("restart", "agentbox-firewall.service"); err != nil {
		return fmt.Errorf("fwcheck: restart agentbox-firewall.service: %v: %s", err, strings.TrimSpace(string(out)))
	}
	// The restart restarts only the units that run: start the ones an earlier failed load or start left down (#218).
	// rootd first: its READY=1 waits for its refill, which ntfy's own fwcheck compares. Agents' user managers start
	// with their next task or attach.
	for _, u := range [][]string{{"agentbox-rootd.service"}, {"agentbox-auditd.service", "agentboxd.service", "agentbox-keys.service", "ntfy.service"}} {
		if out, err := systemctl(append([]string{"start"}, u...)...); err != nil {
			return fmt.Errorf("fwcheck: start %s: %v: %s", strings.Join(u, " "), err, strings.TrimSpace(string(out)))
		}
	}
	for i := 0; i < 15; i++ {
		if bad, err = fwCheck(); err == nil && len(bad) == 0 {
			fmt.Fprintln(os.Stderr, "agentbox: firewall restored")
			alertClear("firewall")
			return nil
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		bad = append(bad, err.Error())
	}
	return errors.New("fwcheck: still altered after the restart: " + strings.Join(bad, "; "))
}

// fwCheck is the table and set checks plus ntfy's: its unit and its running process are _ntfy, the uid the ruleset names.
// A var, like systemctl, so tests can stand in for the box.
var fwCheck = func() ([]string, error) {
	bad, err := fw.Check(fw.RootdDB, time.Now())
	if err := ntfy.CheckUser(); err != nil {
		bad = append(bad, strings.TrimPrefix(err.Error(), "fwcheck: "))
	}
	return bad, err
}

var systemctl = func(args ...string) ([]byte, error) { return exec.Command("systemctl", args...).CombinedOutput() }

// alertDir holds one empty file per standing condition whose alert went out or was queued. It is on tmpfs, so each
// boot alerts again.
var alertDir = "/run/agentbox-alerts"

// alertSock and alertToken are ntfy's socket and agentbox's token for it, and alertDB the rootd.db whose outbox takes
// an alert ntfy doesn't; tests point them at a stand-in.
var alertSock, alertToken, alertDB = ntfy.Socket, ntfy.TokenPath, fw.RootdDB

// alert sends an ALERT on to the human through ntfy, as rootd does, with fixed text: the caller printed the details
// for the journal. A keyed alert names a condition the 50 s health timer sees at each run: it goes out once, and again
// only after alertClear(key). An alert ntfy doesn't take goes in rootd.db's outbox, which rootd sends until ntfy takes
// it (#220). One that can't be queued either is printed, and a keyed one is tried again at the next run.
func alert(key, title, msg string) {
	mark := filepath.Join(alertDir, key)
	if key != "" {
		if _, err := os.Stat(mark); err == nil {
			return
		}
	}
	if err := ntfy.Publish(alertSock, alertToken, ntfy.AlertTopic, title, msg); err == nil {
		fmt.Fprintln(os.Stderr, "agentbox: alert sent:", msg)
	} else if qerr := queueAlert(title, msg); qerr == nil {
		fmt.Fprintf(os.Stderr, "agentbox: alert not sent: %v; queued for rootd to send: %s\n", err, msg)
	} else {
		fmt.Fprintf(os.Stderr, "agentbox: alert not sent: %v; not queued: %v\n", err, qerr)
		return
	}
	if key == "" {
		return
	}
	err := os.MkdirAll(alertDir, 0o700)
	if err == nil {
		err = os.WriteFile(mark, nil, 0o600)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: %v: the next run alerts again\n", err)
	}
}

// alertClear ends key's condition, so its next ALERT goes out.
func alertClear(key string) { os.Remove(filepath.Join(alertDir, key)) }

// queueAlert puts one alert in rootd.db's outbox (ARCHITECTURE.md §11).
func queueAlert(title, msg string) error {
	db, err := rootd.OpenDB(alertDB)
	if err != nil {
		return err
	}
	defer db.Close()
	return rootd.QueueAlert(db, title, msg)
}
