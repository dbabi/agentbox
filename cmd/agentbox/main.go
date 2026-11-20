// Command agentbox is the single binary for every agentbox service and CLI (ARCHITECTURE.md §2, §14).
// Week 1 ships the operator-side commands (seed, recovery) and, on the box, the os.apply pipeline (os); week 3 adds
// the firewall (fw, fwcheck).
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"agentbox/internal/recovery"
	"agentbox/internal/seed"
)

var version = "dev"

const usage = `usage:
  agentbox seed --disk-serial S --ssh-key KEY --password-hash H --minisign-pubkey K --release-url URL --release-sha256 HEX --out DIR
                --encryption tpm2+tang --tang-url U --tang-thp T --recovery-pub recovery.pub   (default mode)
                --encryption tpm2 --recovery-pub recovery.pub | --encryption none
                [--boot uefi|bios] [--hostname agentbox] [--admin boxadmin] [--iso seed.iso] [--dev]
  agentbox recovery keygen --out DIR
  agentbox recovery decrypt --key recovery.key --in recovery.bin --out luks.key
  agentbox os plan --install PKG[=VER] [--install ...] [--remove PKG] [--reinstall]   (on the box, as root)
  agentbox os apply --approve SHA256 [--no-reboot]
  agentbox os health | mark-last-good | status
  agentbox version
  agentbox reconcile   (agentbox-reconcile.service, on the box)
  agentbox fw load [-c] | check [--repair] | refill   (as root on the box; fwcheck = fw check)
`

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	err := run(os.Args[1:])
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return
	case errors.Is(err, errUsage):
		os.Exit(2) // the flag package already printed the problem and the usage
	}
	fmt.Fprintln(os.Stderr, "agentbox:", err)
	os.Exit(1)
}

var errUsage = errors.New("usage")

// parse rejects stray positional arguments: Go's flag package stops at the first one and silently drops every later flag.
func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return errUsage
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%s: unexpected argument %q: every value needs a flag; quote values with spaces, e.g. --ssh-key \"$(cat key.pub)\"", fs.Name(), fs.Arg(0))
	}
	return nil
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return errors.New("missing command")
	}
	switch args[0] {
	case "seed":
		return cmdSeed(args[1:])
	case "recovery":
		return cmdRecovery(args[1:])
	case "os":
		return cmdOS(args[1:])
	case "version":
		fmt.Println(version)
		return nil
	case "reconcile":
		return cmdReconcile(args[1:])
	case "fw":
		return cmdFW(args[1:])
	case "fwcheck":
		return cmdFWCheck(args[1:])
	case "-h", "--help", "help":
		fmt.Print(usage)
		return nil
	}
	return fmt.Errorf("unknown command %q\n%s", args[0], usage)
}

func cmdSeed(args []string) error {
	fs := flag.NewFlagSet("seed", flag.ContinueOnError)
	var c seed.Config
	var keys multi
	var recPub, out, iso string
	fs.StringVar(&c.Hostname, "hostname", "agentbox", "box hostname")
	fs.StringVar(&c.AdminUser, "admin", "boxadmin", "admin user name (installer-reserved names such as admin are refused)")
	fs.StringVar(&c.AdminPasswordHash, "password-hash", "", "yescrypt hash (mkpasswd -m yescrypt), or sha512-crypt with rounds=100000 or more; console and sudo only")
	fs.Var(&keys, "ssh-key", "admin OpenSSH public key line (repeatable)")
	fs.StringVar(&c.DiskSerial, "disk-serial", "", "install disk udev ID_SERIAL; on the target run: udevadm info --query=property --property=ID_SERIAL --value /dev/DISK (lsblk SERIAL is the short form and never matches)")
	fs.StringVar(&c.Boot, "boot", "uefi", "uefi or bios")
	fs.StringVar(&c.Encryption, "encryption", seed.EncTPM2Tang, "tpm2+tang (recommended), tpm2 (disk-removal only), none")
	fs.StringVar(&c.TangURL, "tang-url", "", "Tang server URL, http://<LAN IPv4>[:port] (tpm2+tang)")
	fs.StringVar(&c.TangThp, "tang-thp", "", "Tang signing-key thumbprint (tpm2+tang)")
	fs.StringVar(&recPub, "recovery-pub", "", "recovery.pub from `agentbox recovery keygen` (required unless --encryption=none)")
	fs.StringVar(&c.MinisignPubKey, "minisign-pubkey", "", "release signing public key")
	fs.StringVar(&c.ReleaseURL, "release-url", "", "https URL of the agentbox release tarball")
	fs.StringVar(&c.ReleaseSHA256, "release-sha256", "", "SHA-256 of that tarball (make release prints it): firstboot installs only this release")
	fs.BoolVar(&c.Dev, "dev", false, "QEMU VM only: also accept http://10.0.2.2:PORT release URLs (sha256 and minisign are still checked)")
	fs.StringVar(&out, "out", "", "output directory for user-data and meta-data")
	fs.StringVar(&iso, "iso", "", "also write a NoCloud cidata ISO here (needs xorriso)")
	if err := parse(fs, args); err != nil {
		return err
	}
	if out == "" {
		return errors.New("seed: --out is required")
	}
	c.SSHKeys = keys
	if recPub != "" {
		b, err := os.ReadFile(recPub)
		if err != nil {
			return err
		}
		c.RecoveryPubPEM = b
	}
	if err := seed.WriteNoCloud(&c, out, time.Now()); err != nil {
		return err
	}
	fmt.Printf("wrote %s/user-data and %s/meta-data (0600: user-data holds the admin password hash, keep it private)\n", out, out)
	if iso != "" {
		if err := seed.BuildCidataISO(out, iso); err != nil {
			return err
		}
		fmt.Printf("wrote %s (volume label cidata)\n", iso)
	}
	if c.Encryption == seed.EncTPM2 {
		fmt.Fprintln(os.Stderr, "warning: tpm2 mode protects against disk removal only, not whole-machine theft (ARCHITECTURE.md §3.1)")
	}
	if c.Encryption == seed.EncNone {
		fmt.Fprintln(os.Stderr, "warning: --encryption=none: anyone who takes the disk can read everything on it")
	}
	return nil
}

// cmdReconcile is agentbox-reconcile.service (ARCHITECTURE.md §3.2): it re-applies the persistent control store to
// whichever generation booted, before every agentbox unit. Week 1 skeleton: there is no control store yet.
func cmdReconcile(args []string) error {
	if err := parse(flag.NewFlagSet("reconcile", flag.ContinueOnError), args); err != nil {
		return err
	}
	fmt.Println("reconcile: no control state to re-apply yet")
	return nil
}

func cmdRecovery(args []string) error {
	if len(args) == 0 {
		return errors.New("recovery: expected keygen or decrypt")
	}
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Print(usage)
		return flag.ErrHelp
	}
	fs := flag.NewFlagSet("recovery "+args[0], flag.ContinueOnError)
	switch args[0] {
	case "keygen":
		out := fs.String("out", "", "directory for recovery.key (keep offline) and recovery.pub")
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		if *out == "" {
			return errors.New("recovery keygen: --out is required")
		}
		priv, pub, err := recovery.GenerateKey(*out)
		if err != nil {
			return err
		}
		fmt.Printf("wrote %s (0600: keep it offline; it unlocks the box's disk)\nwrote %s (pass to `agentbox seed --recovery-pub`)\n", priv, pub)
		return nil
	case "decrypt":
		key := fs.String("key", "", "recovery.key")
		in := fs.String("in", "", "recovery.bin copied from /bootpart/agentbox/")
		out := fs.String("out", "", "where to write the LUKS keyfile (0600)")
		if err := parse(fs, args[1:]); err != nil {
			return err
		}
		if *key == "" || *in == "" || *out == "" {
			return errors.New("recovery decrypt: --key, --in and --out are required")
		}
		privPEM, err := os.ReadFile(*key)
		if err != nil {
			return err
		}
		ct, err := os.ReadFile(*in)
		if err != nil {
			return err
		}
		pt, err := recovery.Decrypt(privPEM, ct)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_, err = f.Write(pt)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(*out) // never leave a partial LUKS key behind
			return err
		}
		fmt.Printf("wrote %s: type its 48 digits at the box's disk passphrase prompt, or from rescue media run: cryptsetup open --key-file %s /dev/<root partition> croot\n", *out, *out)
		return nil
	}
	return fmt.Errorf("recovery: unknown subcommand %q", args[0])
}
