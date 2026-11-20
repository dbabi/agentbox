package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"agentbox/internal/fw"
	"agentbox/internal/ntfy"
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
// --repair, which alerts and restarts agentbox-firewall.service (Requires= restarts rootd, the brokers and the agents).
func cmdFWCheck(args []string) error {
	fs := flag.NewFlagSet("fwcheck", flag.ContinueOnError)
	repair := fs.Bool("repair", false, "on a mismatch: alert, restart agentbox-firewall.service, check again")
	if err := parse(fs, args); err != nil {
		return err
	}
	bad, err := fwCheck()
	if err == nil && len(bad) == 0 {
		return nil
	}
	if err != nil {
		bad = append(bad, err.Error())
	}
	if !*repair {
		return errors.New("fwcheck: " + strings.Join(bad, "; "))
	}
	fmt.Fprintf(os.Stderr, "agentbox: ALERT: firewall altered: %s; restarting agentbox-firewall.service\n", strings.Join(bad, "; "))
	if out, err := exec.Command("systemctl", "restart", "agentbox-firewall.service").CombinedOutput(); err != nil {
		return fmt.Errorf("fwcheck: restart agentbox-firewall.service: %v: %s", err, strings.TrimSpace(string(out)))
	}
	// systemctl returns once the firewall is up; rootd's refill runs in the restarts that Requires= queued after it
	for i := 0; i < 15; i++ {
		if bad, err = fwCheck(); err == nil && len(bad) == 0 {
			fmt.Fprintln(os.Stderr, "agentbox: firewall restored")
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
func fwCheck() ([]string, error) {
	bad, err := fw.Check(fw.RootdDB, time.Now())
	if err := ntfy.CheckUser(); err != nil {
		bad = append(bad, strings.TrimPrefix(err.Error(), "fwcheck: "))
	}
	return bad, err
}
