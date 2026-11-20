package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"time"

	"agentbox/internal/rootd"
	"agentbox/internal/rootd/resolve"
	"agentbox/internal/rootd/seal"
)

// AdminSocket is rootd-admin.sock (§2.1): root and agentbox-admin members.
const AdminSocket = "/run/agentbox-rootd/rootd-admin.sock"

// cmdRootd is agentbox-rootd.service.
func cmdRootd(args []string) error {
	fs := flag.NewFlagSet("rootd", flag.ContinueOnError)
	cfg := rootd.Config{DB: "/var/lib/agentbox/rootd.db", EgressDir: resolve.EgressDir, AuditDir: seal.Dir}
	fs.DurationVar(&cfg.ElementTimeout, "element-timeout", 10*time.Minute, "dst set element timeout (Appendix B: 10m; shorter only for test VMs)")
	fs.DurationVar(&cfg.RefillInterval, "refill-interval", 5*time.Minute, "timer refill and ntfy_dst refresh (§6.1: 5m)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if cfg.ElementTimeout < 10*time.Second || cfg.ElementTimeout > 10*time.Minute || cfg.RefillInterval < 5*time.Second || cfg.RefillInterval >= cfg.ElementTimeout {
		return errors.New("rootd: need 10s <= --element-timeout <= 10m and 5s <= --refill-interval < --element-timeout (ntfy_dst must refresh before it expires)")
	}
	return rootd.Run(cfg)
}

// cmdEgress is the admin CLI for the broker allowlists, over rootd-admin.sock.
func cmdEgress(args []string) error {
	if len(args) == 0 {
		return errors.New("egress: expected list, allow, remove or refill")
	}
	fs := flag.NewFlagSet("egress "+args[0], flag.ContinueOnError)
	req := map[string]any{}
	switch args[0] {
	case "allow", "remove":
		svc := fs.String("svc", "", "broker: keys or git (service.list), or proxy (common.list)")
		entry := fs.String("entry", "", "host:port")
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		if *svc == "" || *entry == "" {
			return fmt.Errorf("egress %s: --svc and --entry are required", args[0])
		}
		req = map[string]any{"op": "egress." + args[0], "svc": *svc, "entry": *entry}
	case "list", "refill":
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		req["op"] = map[string]string{"list": "egress.list", "refill": "sets.refill"}[args[0]]
	default:
		return fmt.Errorf("egress: unknown subcommand %q", args[0])
	}
	c, err := net.Dial("unix", AdminSocket)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(60 * time.Second))
	b, _ := json.Marshal(req)
	if _, err := c.Write(append(b, '\n')); err != nil {
		return err
	}
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("rootd closed the connection: %v", err)
	}
	fmt.Print(string(line))
	var rep struct {
		OK bool `json:"ok"`
	}
	if json.Unmarshal(line, &rep) != nil || !rep.OK {
		return errors.New("egress: refused")
	}
	return nil
}
