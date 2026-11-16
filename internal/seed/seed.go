// Package seed renders the NoCloud autoinstall seed for a stock Ubuntu Server
// 26.04 ISO (ARCHITECTURE.md §3.1, Appendix A).
//
// Every operator-supplied value crosses a trust boundary into YAML and into a
// root shell script that runs in the installer, so each one is validated
// against a strict pattern before rendering. YAML scalars are emitted as JSON
// strings (valid YAML). Shell-embedded values use charsets that cannot contain
// a single quote.
package seed

import (
	"bytes"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
	"time"

	"agentbox/internal/recovery"
)

//go:embed user-data.tmpl
var userDataTmpl string

// Encryption modes (ARCHITECTURE.md §3.1).
const (
	EncTPM2Tang = "tpm2+tang"
	EncTPM2     = "tpm2"
	EncNone     = "none"
)

// Config is everything `agentbox seed` needs: public keys plus the admin password hash (keep the seed private).
type Config struct {
	Hostname          string
	AdminUser         string
	AdminPasswordHash string   // sha512-crypt ($6$...), e.g. from `openssl passwd -6`
	SSHKeys           []string // OpenSSH public keys
	DiskSerial        string   // udev ID_SERIAL: `udevadm info --query=property --property=ID_SERIAL --value /dev/DISK`
	Boot              string   // "uefi" | "bios"
	Encryption        string   // EncTPM2Tang | EncTPM2 | EncNone
	TangURL           string   // required for tpm2+tang
	TangThp           string   // Tang signing-key thumbprint (`tang-show-keys`), required for tpm2+tang
	RecoveryPubPEM    []byte   // RSA-4096 PKIX PEM; required unless Encryption is none
	MinisignPubKey    string   // release verification key
	ReleaseURL        string   // https URL of the agentbox release tarball
}

var (
	reHostname = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	reUser     = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	reSHA512   = regexp.MustCompile(`^\$6\$(rounds=[0-9]{4,9}\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{85}[./01]$`)
	reSSHKey   = regexp.MustCompile(`^(ssh-ed25519|sk-ssh-ed25519@openssh\.com|ecdsa-sha2-nistp(256|384|521)|ssh-rsa) [A-Za-z0-9+/]+={0,3}( [A-Za-z0-9@._+-]{1,128})?$`)
	reSerial   = regexp.MustCompile(`^[A-Za-z0-9._:#+=@-]{1,128}$`) // udev ID_SERIAL charset minus nothing a shell or YAML cares about
	reMinisign = regexp.MustCompile(`^RW[A-Za-z0-9+/]{54}$`)
	reHTTPS    = regexp.MustCompile(`^https://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$`)
	reTangURL  = regexp.MustCompile(`^http://([0-9]{1,3}(\.[0-9]{1,3}){3})(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$`)
	reThp      = regexp.MustCompile(`^[A-Za-z0-9_-]{20,128}$`)
)

// Validate reports every problem at once, so the operator can fix them in one pass.
func (c *Config) Validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	if !reHostname.MatchString(c.Hostname) {
		bad("hostname %q: lowercase RFC 1123 label required", c.Hostname)
	}
	if !reUser.MatchString(c.AdminUser) {
		bad("admin user %q: invalid Linux user name", c.AdminUser)
	} else if reservedUser(c.AdminUser) {
		bad("admin user %q: reserved by the Ubuntu 26.04 installer or by agentbox accounts; use e.g. boxadmin", c.AdminUser)
	}
	if !reSHA512.MatchString(c.AdminPasswordHash) {
		bad("admin password hash: need sha512-crypt ($6$...); create one with `openssl passwd -6`")
	}
	if len(c.SSHKeys) == 0 {
		bad("at least one --ssh-key is required (SSH password login is disabled)")
	}
	for _, k := range c.SSHKeys {
		if !reSSHKey.MatchString(k) || !sshKeyOK(k) {
			bad("ssh key %.40q…: not a valid OpenSSH public key line (or the comment has unsupported characters)", k)
		}
	}
	if !reSerial.MatchString(c.DiskSerial) {
		bad("disk serial %q: the disk's udev ID_SERIAL is required ([A-Za-z0-9._:#+=@-]); on the target run "+
			"`udevadm info --query=property --property=ID_SERIAL --value /dev/DISK` (lsblk SERIAL is the short form and never matches)", c.DiskSerial)
	}
	if c.Boot != "uefi" && c.Boot != "bios" {
		bad("boot %q: must be uefi or bios", c.Boot)
	}
	switch c.Encryption {
	case EncTPM2Tang:
		if m := reTangURL.FindStringSubmatch(c.TangURL); m == nil {
			bad("tang url %q: http://<LAN IPv4>[:port][/path] required (the 26.04 dracut initramfs has no DNS resolver or CA bundle)", c.TangURL)
		} else if ip, err := netip.ParseAddr(m[1]); err != nil || !ip.IsPrivate() {
			bad("tang url %q: %s is not a private LAN address; tpm2+tang protects away from home only if Tang is unreachable from outside", c.TangURL, m[1])
		}
		if !reThp.MatchString(c.TangThp) {
			bad("tang thp %q: base64url thumbprint required for tpm2+tang (run `tang-show-keys` on the Tang host)", c.TangThp)
		}
	case EncTPM2, EncNone:
		if c.TangURL != "" || c.TangThp != "" {
			bad("tang url/thp only apply to --encryption=tpm2+tang")
		}
	default:
		bad("encryption %q: must be tpm2+tang, tpm2 or none", c.Encryption)
	}
	encrypted := c.Encryption == EncTPM2Tang || c.Encryption == EncTPM2
	switch {
	case c.Encryption == EncNone && len(c.RecoveryPubPEM) > 0:
		bad("--recovery-pub only applies to encrypted modes")
	case encrypted && len(c.RecoveryPubPEM) == 0:
		bad("--recovery-pub is required for --encryption=%s (create one with `agentbox recovery keygen`)", c.Encryption)
	case encrypted:
		if _, err := recovery.ParsePublic(c.RecoveryPubPEM); err != nil {
			bad("%v (create one with `agentbox recovery keygen`)", err)
		}
	}
	if mk, err := base64.StdEncoding.DecodeString(c.MinisignPubKey); !reMinisign.MatchString(c.MinisignPubKey) || err != nil || len(mk) != 42 || string(mk[:2]) != "Ed" {
		bad("minisign public key: expected the 56-char Ed25519 minisign key starting with RW")
	}
	if !reHTTPS.MatchString(c.ReleaseURL) {
		bad("release url %q: https://host[:port]/path without query string required", c.ReleaseURL)
	}
	return errors.Join(errs...)
}

// sshKeyOK checks the key blob's wire format: its type string must equal the line's key type.
func sshKeyOK(line string) bool {
	f := strings.Fields(line)
	b, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil || len(b) < 4 {
		return false
	}
	n := int(binary.BigEndian.Uint32(b))
	if n > len(b)-4 || string(b[4:4+n]) != f[0] {
		return false
	}
	switch f[0] {
	case "ssh-ed25519":
		return len(b) == 4+n+4+32
	case "ssh-rsa": // wire format: string type, mpint e, mpint n; refuse moduli under 3072 bits
		rest := b[4+n:]
		for i := 0; i < 2; i++ {
			if len(rest) < 4 {
				return false
			}
			l := int(binary.BigEndian.Uint32(rest))
			if l > len(rest)-4 {
				return false
			}
			if i == 1 {
				return new(big.Int).SetBytes(rest[4:4+l]).BitLen() >= 3072
			}
			rest = rest[4+l:]
		}
		return false
	}
	return len(b) > 4+n
}

type view struct {
	Config
	Encrypted      bool
	BIOS           bool
	Packages       string
	KernelArgs     string
	ClevisPin      string
	ClevisConfig   string
	RecoveryPubCmd string
	DiskGuardCmd   string
}

func (c *Config) view() (view, error) {
	v := view{Config: *c, Encrypted: c.Encryption != EncNone, BIOS: c.Boot == "bios"}
	pkgs := []string{"btrfs-progs", "minisign", "nftables", "podman", "crun", "systemd-container",
		"systemd-zram-generator", "curl", "openssl"}
	v.KernelArgs = "panic=10 rd.emergency=reboot rd.shell=0"
	// subiquity binds `serial:` to the first probed disk with an equal udev ID_SERIAL and never reports duplicates;
	// curtin's storage v1 then re-resolves the serial by /dev/disk/by-id substring. Stop before storage runs unless
	// exactly one disk has this ID_SERIAL and no other device's by-id name contains it. Prints every disk's ID_SERIAL.
	v.DiskGuardCmd = `udevadm settle; S='` + c.DiskSerial + `'; n=0; D=; for b in /sys/block/*; do ` +
		`s=$(udevadm info --query=property --property=ID_SERIAL --value "$b" 2>/dev/null); ` +
		`echo "agentbox: disk ${b##*/} ID_SERIAL=$s" >&2; [ "$s" = "$S" ] && { n=$((n+1)); D=${b##*/}; }; done; ` +
		`[ "$n" -eq 1 ] || { echo "agentbox: --disk-serial $S matched $n disks, need exactly 1" >&2; exit 1; }; ` +
		`for l in /dev/disk/by-id/*"$S"*; do [ -e "$l" ] || continue; r=$(readlink -f "$l"); r=${r##*/}; ` +
		`[ -e "/sys/class/block/$r/partition" ] && r=$(basename "$(dirname "$(readlink -f "/sys/class/block/$r")")"); ` +
		`[ "$r" = "$D" ] || { echo "agentbox: $l also contains $S (curtin matches by-id substrings)" >&2; exit 1; }; done`
	if v.Encrypted {
		pkgs = append(pkgs, "cryptsetup", "clevis", "clevis-luks", "clevis-tpm2", "clevis-dracut", "tpm2-tools")
		rk, err := recovery.ParsePublic(c.RecoveryPubPEM)
		if err != nil {
			return v, err
		}
		der, err := x509.MarshalPKIXPublicKey(rk)
		if err != nil {
			return v, err
		}
		// Render the key that was validated, never the operator's bytes (Go and OpenSSL pick different PEM blocks).
		lines := strings.Split(strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))), "\n")
		for i, l := range lines {
			lines[i] = "'" + l + "'"
		}
		v.RecoveryPubCmd = "printf '%s\\n' " + strings.Join(lines, " ") + " > /run/agentbox-recovery.pub"
	}
	switch c.Encryption {
	case EncTPM2:
		// No PCR policy: PCR 7 adds nothing against the documented threats (signed live media reproduces it) and breaks
		// unattended unlock on SBAT/dbx/Secure Boot changes; clevis 20 also defaults pcr_bank to sha1.
		v.ClevisPin, v.ClevisConfig = "tpm2", `{}`
	case EncTPM2Tang:
		// The tang pin ships in the core `clevis` package (no separate clevis-tang binary package in resolute).
		cfg, err := json.Marshal(map[string]any{
			"t": 2,
			"pins": map[string]any{
				"tpm2": map[string]string{},
				"tang": []map[string]string{{"url": c.TangURL, "thp": c.TangThp}},
			},
		})
		if err != nil {
			return v, err
		}
		v.ClevisPin, v.ClevisConfig = "sss", string(cfg)
		v.KernelArgs += " ip=dhcp rd.neednet=1" // Tang must be reachable from the initramfs
	}
	v.Packages = strings.Join(pkgs, ", ")
	return v, nil
}

// Render validates c and returns the autoinstall user-data.
func Render(c *Config) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	v, err := c.view()
	if err != nil {
		return nil, err
	}
	t, err := template.New("user-data").Option("missingkey=error").Funcs(template.FuncMap{
		"json": func(s string) (string, error) { b, err := json.Marshal(s); return string(b), err },
	}).Parse(userDataTmpl)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// WriteNoCloud writes user-data and meta-data into dir, private to the operator (user-data holds the password hash).
func WriteNoCloud(c *Config, dir string, now time.Time) error {
	ud, err := Render(c)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	md := fmt.Sprintf("instance-id: agentbox-%s-%d\n", c.Hostname, now.Unix())
	for name, b := range map[string][]byte{"user-data": ud, "meta-data": []byte(md)} {
		f, err := os.CreateTemp(dir, "."+name+"-*") // O_EXCL, mode 0600, never follows a planted symlink
		if err != nil {
			return err
		}
		if _, err := f.Write(b); err != nil {
			f.Close()
			os.Remove(f.Name())
			return err
		}
		if err := f.Close(); err != nil {
			os.Remove(f.Name())
			return err
		}
		if err := os.Rename(f.Name(), filepath.Join(dir, name)); err != nil {
			os.Remove(f.Name())
			return err
		}
	}
	return nil
}

// BuildCidataISO packs dir (user-data, meta-data) into a NoCloud "cidata" ISO with xorriso.
func BuildCidataISO(dir, out string) error {
	x, err := exec.LookPath("xorriso")
	if err != nil {
		return errors.New("xorriso not found (brew install xorriso / apt install xorriso)")
	}
	cmd := exec.Command(x, "-no_rc", "-as", "mkisofs", "-quiet", "-o", out, "-V", "cidata", "-J", "-r",
		filepath.Join(dir, "user-data"), filepath.Join(dir, "meta-data"))
	if msg, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("xorriso: %v: %s", err, bytes.TrimSpace(msg))
	}
	return os.Chmod(out, 0o600) // the ISO carries the password hash too
}
