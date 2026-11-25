package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"agentbox/internal/rootd/gens"
	"agentbox/internal/rootd/quota"
)

// cmdOS runs `agentbox os ...` as root on the box (ARCHITECTURE.md §3.3). Week 1 runs the os.apply pipeline from
// the CLI; rootd takes it over with signed approvals in weeks 9-12.
func cmdOS(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("os: expected plan, apply, health, mark-last-good or status\n%s", usage)
	}
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Print(usage)
		return flag.ErrHelp
	}
	if os.Getenv("AGENTBOX_OS_NS") != "1" {
		// Re-run in a private mount namespace (like PrivateMounts=yes): the btrfs top-level mount never shows on
		// the host and vanishes with the command, even on a crash.
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		unshare, err := exec.LookPath("unshare")
		if err != nil {
			return fmt.Errorf("os: %v (agentbox os runs on the box)", err)
		}
		argv := append([]string{"unshare", "--mount", "--propagation", "private", exe, "os"}, args...)
		return syscall.Exec(unshare, argv, append(os.Environ(), "AGENTBOX_OS_NS=1"))
	}
	gens.AfterDelete = qgroupCheck
	gens.Alert = func(title, msg string) { alert("", title, msg) }
	fs := flag.NewFlagSet("os "+args[0], flag.ContinueOnError)
	switch args[0] {
	case "plan":
		var inst, rm multi
		fs.Var(&inst, "install", "package or package=version to install or upgrade (repeatable)")
		fs.Var(&rm, "remove", "package to remove (repeatable)")
		reinstall := fs.Bool("reinstall", false, "also re-install named packages that are already at that version")
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		req := []string(inst)
		for _, r := range rm {
			req = append(req, r+"-")
		}
		if len(req) == 0 {
			return errors.New("os plan: give at least one --install or --remove")
		}
		p, h, err := gens.MakePlan(req, *reinstall)
		if err != nil {
			return err
		}
		fmt.Print(p.Print(h))
		return nil
	case "apply":
		approve := fs.String("approve", "", "sha256 of the plan, as `agentbox os plan` printed it")
		noReboot := fs.Bool("no-reboot", false, "set up the one-time boot but don't reboot now")
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		if len(*approve) != 64 || strings.Trim(*approve, "0123456789abcdef") != "" {
			return errors.New("os apply: --approve needs the plan's sha256 (64 hex digits)")
		}
		unlock, err := gens.Lock(true)
		if err != nil {
			return err
		}
		defer unlock()
		top, err := mountTop()
		if err != nil {
			return err
		}
		p, err := gens.Build(*approve, top)
		if err != nil {
			return err
		}
		fmt.Printf("built %s: the next boot tries %s once; health commits it, anything else falls back\n", p.Gen, p.Entry)
		if *noReboot {
			return nil
		}
		return exec.Command("systemctl", "reboot").Run()
	case "health":
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		return osHealth()
	case "mark-last-good":
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		unlock, err := gens.Lock(true)
		if err != nil {
			return err
		}
		defer unlock()
		top, err := mountTop()
		if err != nil {
			return err
		}
		return gens.MarkLastGood(top)
	case "status":
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		return osStatus()
	}
	return fmt.Errorf("os: unknown subcommand %q", args[0])
}

// qgroupCheck is gens.AfterDelete. Once Linux has dropped the generation subvolumes this command deleted, and removed
// their qgroups (quota.Dropped), the qgroup flag says whether the drop left qgroups inconsistent, so 1/N and 2/0 limit
// nothing. rootd's quota.check then fences, rescans and thaws at once, not at its 5-minute timer (#209). That timer is
// all that is left when this fails, so a failure alerts.
func qgroupCheck(ids []string) error {
	err := quota.Dropped(ids...)
	var line []byte
	var cerr error
	// "fenced" while another check holds rootd's fence lock: that check may have read the flag before the drop set it,
	// so ask again until rootd itself checked. A repair keeps the fence up for as long as it takes.
	for i := 0; i < 300; i++ {
		if i > 0 {
			time.Sleep(2 * time.Second)
		}
		var rep struct {
			Fenced bool `json:"fenced"`
		}
		if line, cerr = adminLine(map[string]any{"op": "quota.check"}, "rootd quota check"); cerr != nil || json.Unmarshal(line, &rep) != nil || !rep.Fenced {
			break
		}
	}
	if err = errors.Join(err, cerr); err != nil {
		fmt.Fprintf(os.Stderr, "agentbox: ALERT: qgroups not checked after deleting subvolumes %s: %v %s\n", strings.Join(ids, " "), err, bytes.TrimSpace(line))
		alert("", "agentbox: disk quotas", "qgroups were not checked after agentbox os deleted generation subvolumes, so the disk reserve may limit nothing until rootd's 5-minute check")
		return err
	}
	fmt.Fprintf(os.Stderr, "os: qgroups checked after deleting subvolumes %s: %s\n", strings.Join(ids, " "), bytes.TrimSpace(line))
	return nil
}

// mountTop mounts the btrfs top level at a fixed dir (gens.Mounts); the mounts exist only in this command's namespace.
func mountTop() (string, error) {
	top := "/run/agentbox-os"
	if err := os.MkdirAll(top, 0o700); err != nil {
		return "", err
	}
	return top, gens.Mounts(top)
}

// osHealth runs from agentbox-health.timer. On the booted trial it commits once healthy, and otherwise waits: the
// boot deadline falls back. On the committed generation it drops deleted generations from grub.cfg (gens.FixGrub).
// It exits 0 unless it can't run, so a not-yet-healthy trial never fails a unit.
func osHealth() error {
	unlock, err := gens.Lock(false)
	if err != nil {
		fmt.Println(err) // an apply is running; the timer comes back
		return nil
	}
	defer unlock()
	p, err := gens.Settle()
	if err != nil {
		return err
	}
	bad := gens.Health()
	for _, b := range bad {
		fmt.Fprintln(os.Stderr, "agentbox: health:", b)
	}
	if p != nil {
		gen, k, err := gens.Booted()
		if err != nil {
			return err
		}
		if p.Entry != gens.Entry(gen, k) { // built in this boot, not booted yet
			return nil
		}
		if len(bad) > 0 {
			fmt.Fprintf(os.Stderr, "agentbox: health: trial %s not committed yet; the boot deadline falls back unless it gets healthy\n", p.Entry)
			return nil
		}
		top, err := mountTop()
		if err != nil {
			return err
		}
		return gens.Commit(p, top)
	}
	gen, k, err := gens.Booted()
	if err != nil {
		return err
	}
	if c, err := gens.CommittedEntry(); err != nil || c != gens.Entry(gen, k) {
		fmt.Fprintf(os.Stderr, "agentbox: ALERT: booted %s is not the committed %q (%v); the boot deadline returns to it\n", gens.Entry(gen, k), c, err)
		alert("uncommitted-boot", "agentbox: health", "the box booted a generation that is not the committed one: the boot deadline reboots into the committed one")
		return nil // update-grub runs only the committed generation's grub.d
	}
	alertClear("uncommitted-boot")
	if len(bad) > 0 {
		fmt.Fprintln(os.Stderr, "agentbox: ALERT: the committed generation is unhealthy (see above)")
		alert("unhealthy", "agentbox: health", "the committed generation is unhealthy: journalctl -u agentbox-health.service names the failed checks")
	} else {
		alertClear("unhealthy")
	}
	return gens.FixGrub()
}

func osStatus() error {
	gen, k, err := gens.Booted()
	if err != nil {
		return err
	}
	env, err := gens.ReadGrubEnv()
	if err != nil {
		return err
	}
	c, cerr := gens.CommittedEntry()
	if cerr != nil {
		c = "(" + cerr.Error() + ")"
	}
	fmt.Printf("booted:      %s\ncommitted:   %s\nsaved_entry: %s\nnext_entry:  %s\n", gens.Entry(gen, k), c, env["saved_entry"], env["next_entry"])
	p, err := gens.ReadPending()
	if err != nil {
		return err
	}
	if p != nil {
		fmt.Printf("pending:     %s (plan %s)\n", p.Entry, p.Plan)
	}
	failed, _ := filepath.Glob(filepath.Join(gens.StateDir, "failed", "gen-*.json"))
	for _, f := range failed {
		b, _ := os.ReadFile(f)
		fmt.Printf("failed:      %s", b)
	}
	top, err := mountTop()
	if err != nil {
		return err
	}
	all, err := gens.Generations(top)
	if err != nil {
		return err
	}
	for _, n := range all {
		g := gens.Gen(n)
		var ks []string
		if es, err := os.ReadDir(filepath.Join(gens.GensDir, g)); err == nil {
			var names []string
			for _, e := range es {
				names = append(names, e.Name())
			}
			ks = gens.Kernels(names)
		}
		_, serr := os.Stat(filepath.Join(top, "@"+g))
		fmt.Printf("%-7s subvolume=%-5v kernels=%s\n", g, serr == nil, strings.Join(ks, ","))
	}
	return nil
}
