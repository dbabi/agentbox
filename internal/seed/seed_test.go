package seed

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"agentbox/internal/recovery"
)

// One RSA-4096 key per test binary: generating one per subtest made TestValidateRejects take ~10 s.
var testPub = sync.OnceValues(func() ([]byte, error) {
	dir, err := os.MkdirTemp("", "agentbox-seed-test")
	if err != nil {
		return nil, err
	}
	_, pub, err := recovery.GenerateKey(dir)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(pub)
})

func testSSHKey(t testing.TB) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var b []byte
	for _, f := range [][]byte{[]byte("ssh-ed25519"), pub} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(f)))
		b = append(b, f...)
	}
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(b) + " you@laptop"
}

func validConfig(t testing.TB, enc, boot string) *Config {
	t.Helper()
	c := &Config{
		Hostname:          "agentbox",
		AdminUser:         "boxadmin",
		AdminPasswordHash: "$y$j9T$agentboxgatesalt0000$nVjZH1ZaNBH.vEdKjhLQLZVUy6bJDJKQOxEO8qRil23", // libxcrypt crypt("x")
		SSHKeys:           []string{testSSHKey(t)},
		DiskSerial:        "Samsung_SSD_870_EVO_500GB_S4EVNX0N123456",
		Boot:              boot,
		Encryption:        enc,
		MinisignPubKey:    "RWQ" + strings.Repeat("A", 53), // decodes to "Ed..."
		ReleaseURL:        "https://releases.example.com/agentbox/agentbox-2026.11.1.tgz",
		ReleaseSHA256:     testSHA,
	}
	if enc == EncTPM2Tang {
		c.TangURL, c.TangThp = "http://192.168.1.10:7500", "_OsIk0T-E2l6qjfdDiwVmidoZjA"
	}
	if enc != EncNone {
		pub, err := testPub()
		if err != nil {
			t.Fatal(err)
		}
		c.RecoveryPubPEM = pub
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("baseline config invalid: %v", err)
	}
	return c
}

const testSHA = "5a4f3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a"

// RE2's . stops at a newline, so this sees the bind line only; -[A-Za-z]*y finds y in any short-option cluster
var reTrustsTang = regexp.MustCompile(`clevis luks bind.*[ \t]-[A-Za-z]*y`)

// trustsTang reports whether a clevis luks bind line in s passes -y, which skips checking Tang's advertisement
// against thp. A line continued with a trailing backslash counts as one line.
func trustsTang(s string) bool { return reTrustsTang.MatchString(strings.ReplaceAll(s, "\\\n", " ")) }

// TestTrustsTang checks the -y guard itself: the old pattern never matched -y right after bind.
func TestTrustsTang(t *testing.T) {
	for _, f := range []string{"-y -k f", "-yk f", "-yk/run/k", "-fy -k f", "-k f -d d -y", "-k f -yd d", " -y", "\t-y", "-k f \\\n        -y -d d"} {
		if !trustsTang("      chroot /mnt/new clevis luks bind " + f + " sss '{}'\n") {
			t.Errorf("misses -y in %q", f)
		}
	}
	if trustsTang("      chroot /mnt/new clevis luks bind -k /run/agentbox-luks.key -d \"$LUKSDEV\" sss '{\"t\":2}'\n" +
		"      chroot /mnt/new env DEBIAN_FRONTEND=noninteractive apt-get purge -y kdump-tools\n") {
		t.Error("flags a -y on a later line")
	}
}

func TestRenderModes(t *testing.T) {
	encWant := map[string][]string{
		EncTPM2Tang: {"keyfile: /run/agentbox-luks.key, options: [luks, x-initrd.attach, timeout=300s]}",
			"{type: format, id: froot, volume: croot, fstype: btrfs}", "ip=dhcp rd.neednet=1",
			`sss '{"pins":{"tang":[{"thp":"_OsIk0T-E2l6qjfdDiwVmidoZjA","url":"http://192.168.1.10:7500"}],"tpm2":{}},"t":2}'`,
			"clevis-dracut", "dracut -f --regenerate-all", "head -c 48", "shred -u /run/agentbox-luks.key", "-pkeyopt rsa_oaep_md:sha256",
			"test -c /dev/tpmrm0",
			// Appendix A items 1-2: forced dracut modules and every kernel's initrd checks, per mode
			`'add_dracutmodules+=" btrfs systemd-cryptsetup clevis clevis-pin-sss clevis-pin-tpm2 clevis-pin-tang "'`,
			"for f in btrfs.ko systemd-cryptsetup clevis-luks-askpass clevis-decrypt-sss clevis-decrypt-tpm2 clevis-decrypt-tang; do",
			`lsinitrd -f etc/crypttab "/boot/initrd.img-$k" | grep -q '^croot '`, `readlink -f "$LUKSDEV"`},
		EncTPM2: {"{type: format, id: froot, volume: croot, fstype: btrfs}", ` tpm2 '{}'`, "clevis-dracut",
			"shred -u /run/agentbox-luks.key", "-pkeyopt rsa_oaep_md:sha256", "test -c /dev/tpmrm0",
			`'add_dracutmodules+=" btrfs systemd-cryptsetup clevis clevis-pin-tpm2 "'`,
			"for f in btrfs.ko systemd-cryptsetup clevis-luks-askpass clevis-decrypt-tpm2; do",
			`lsinitrd -f etc/crypttab "/boot/initrd.img-$k" | grep -q '^croot '`, `readlink -f "$LUKSDEV"`},
		EncNone: {"{type: format, id: froot, volume: proot, fstype: btrfs}", `'add_dracutmodules+=" btrfs "'`, "for f in btrfs.ko; do",
			`readlink -f "$DEV"`},
	}
	encAvoid := map[string][]string{
		EncTPM2Tang: {"volume: proot, fstype: btrfs", "pcr_ids", "clevis-tang", "head -c 64"}, // the tang pin is in clevis
		EncTPM2:     {"volume: proot, fstype: btrfs", "ip=dhcp", " sss ", "pcr_ids", "clevis-pin-tang", "clevis-decrypt-tang", "clevis-pin-sss"},
		EncNone:     {"dm_crypt", "clevis", "cryptsetup", "recovery", "ip=dhcp", "agentbox-luks.key", "tpmrm0", "lsinitrd -f etc/crypttab"},
	}
	bootWant := map[string][]string{
		"uefi": {"{type: partition, id: esp, device: d0, number: 1, size: 1G, flag: boot, grub_device: true}", "mount --bind /target/boot/efi /mnt/new/boot/efi"},
		"bios": {"wipe: superblock-recursive, preserve: false, grub_device: true}", "{type: partition, id: bg, device: d0, number: 1, size: 1M, flag: bios_grub}"},
	}
	bootAvoid := map[string][]string{"uefi": {"bios_grub"}, "bios": {"id: esp", "fat32", "/boot/efi"}}
	common := []string{"apt: {fallback: abort}", "kernel-crash-dumps: {enabled: false}", `S='Samsung_SSD_870_EVO_500GB_S4EVNX0N123456'`,
		"dists/resolute/InRelease", "btrfs subvolume list -o /target", "mount --make-private /mnt/new/bootpart",
		`mount --make-rslave "/mnt/new/$d"`, "set fallback=%s", "sort -V", "insmod gzio", "rm -f /var/log/installer/autoinstall-user-data /var/log/installer/curtin-install*.yaml",
		`mount -o subvol=@var_log "$DEV" /target/var/log`, "D=/run/agentbox-firstboot", "RuntimeDirectory=agentbox-firstboot", "RuntimeDirectoryMode=0700", "PrivateMounts=yes",
		"@var_lib_agentbox_data /var/lib/agentbox/data", "mkdir -m 0755 /target/@var_lib_agentbox/data", "ports.ubuntu.com/ubuntu-ports",
		"systemctl mask apt-daily.timer apt-daily-upgrade.timer", "RuntimeMaxSec=120", "panic=10 rd.emergency=reboot rd.shell=0 rd.timeout=600",
		// Appendix A item 1: 90-agentbox.conf, with the root disk's driver chain and the watchdog driver from this hardware
		`printf '%s\n' 'hostonly="yes"' 'hostonly_cmdline="no"' 'add_dracutmodules+="`, `"add_drivers+=\"$DRV \"" "force_drivers+=\" ${WD:=softdog} \"" > /mnt/new/etc/dracut.conf.d/90-agentbox.conf`,
		`DRV="$DRV $(basename "$(readlink -f "$p/driver/module")")"`, "/drivers/watchdog/",
		// item 2: every kernel's initrd, including the recorded driver modules
		`for k in $(ls /mnt/new/boot | sed -n 's/^vmlinuz-//p'); do chroot /mnt/new lsinitrd "/boot/initrd.img-$k" > /tmp/initrd.lst`,
		`for m in $DRV $WD; do f=$(chroot /mnt/new modinfo -k "$k" -F filename "$m")`,
		// item 4, watchdog half
		`printf '%s\n' '[Manager]' 'RuntimeWatchdogSec=60s' > $G/etc/systemd/system.conf.d/50-agentbox.conf`,
		// item 5, plus the snapd and dbx policy
		"systemctl mask nftables.service snapd.socket snapd.service snapd.seeded.service snapd.snap-repair.timer \\\n        lxd-installer.socket secureboot-db.service",
		"chroot /mnt/new systemctl mask grub2-common.service grub-initrd-fallback.service\n", // no in-place grubenv rewrites at boot
		"chroot /mnt/new env DEBIAN_FRONTEND=noninteractive apt-get purge -y kdump-tools", "test ! -e /mnt/new/etc/default/grub.d/kdump-tools.cfg",
		`[ -z "$U" ] || chroot /mnt/new env DEBIAN_FRONTEND=noninteractive apt-get install -y $U`,
		// item 6
		"control state (rootd.db, audit, taint.db) that stays in @var_lib_agentbox",
		"mountpoint -q /dev/pts; mountpoint -q /sys/fs/cgroup",
		// day 4: the committed file 09_agentbox falls back to, and the commit deadline
		`printf '%s\n' "agentbox-gen-1-$KV" > /mnt/new/bootpart/agentbox/committed`, "systemctl enable agentbox-boot-deadline.service",
		"'DefaultDependencies=no'", "'WantedBy=sysinit.target'"}
	for _, enc := range []string{EncTPM2Tang, EncTPM2, EncNone} {
		for _, boot := range []string{"uefi", "bios"} {
			t.Run(enc+"/"+boot, func(t *testing.T) {
				out, err := Render(validConfig(t, enc, boot))
				if err != nil {
					t.Fatal(err)
				}
				s := string(out)
				for _, w := range append(append(append([]string{}, common...), encWant[enc]...), bootWant[boot]...) {
					if !strings.Contains(s, w) {
						t.Errorf("missing %q", w)
					}
				}
				for _, a := range append(append([]string{"/tmp/ab", "| head -1", "mktemp -d /run/agentbox-firstboot", "state.db, audit", "modules-load.d"}, encAvoid[enc]...), bootAvoid[boot]...) {
					if strings.Contains(s, a) {
						t.Errorf("unexpected %q", a)
					}
				}
				if i, j := strings.Index(s, "early-commands:"), strings.Index(s, "need exactly 1"); i < 0 || j < i || strings.Count(s[i:j], "\n    - ") != 1 {
					t.Error("the disk guard must be early-commands[0]")
				}
				// firstboot: capped downloads, the sha256 pin, then minisign, and only then does anything unpack or install.
				// It starts the firewall and the rest after reconcile, and is done only once they run (#218).
				last := -1
				for _, step := range []string{"--max-filesize 64M", `h=$(sha256sum "$D/ab.tgz")`, `[ "$h" = "$AGENTBOX_RELEASE_SHA256" ] || {`,
					`minisign -Vm "$D/ab.tgz" -P "$AGENTBOX_MINISIGN_PUBKEY" || {`, `tar -xzf "$D/ab.tgz"`, `"$D/x/install.sh" --from-firstboot`,
					"systemctl start agentbox-reconcile.service", "os mark-last-good",
					"systemctl start agentbox-firewall.service agentbox-rootd.service\n",
					"systemctl start agentbox-auditd.service agentboxd.service agentbox-keys.service ntfy.service sockets.target timers.target\n",
					"touch /var/lib/agentbox/.firstboot-done", "'AGENTBOX_RELEASE_SHA256=" + testSHA + "'"} {
					i := strings.Index(s, step)
					if i <= last {
						t.Errorf("firstboot step %q missing or out of order", step)
					}
					last = i
				}
				if trustsTang(s) {
					t.Error("clevis luks bind must not auto-trust Tang (-y)")
				}
				for _, leak := range []string{"<no value>", "{{"} {
					if strings.Contains(s, leak) {
						t.Errorf("template residue %q", leak)
					}
				}
				if strings.Contains(s, "PRIVATE KEY") {
					t.Fatal("private key material in seed")
				}
				inBlock := false
				for _, l := range strings.Split(s, "\n") {
					if strings.HasPrefix(l, "    - |") {
						inBlock = true
						continue
					}
					if inBlock && l != "" && !strings.HasPrefix(l, "      ") {
						t.Fatalf("late-commands line lost indentation: %q", l)
					}
				}
			})
		}
	}
}

func TestValidateRejects(t *testing.T) {
	weak := func() []byte {
		k, _ := rsa.GenerateKey(rand.Reader, 4096)
		pk := k.PublicKey
		pk.E = 1
		der, _ := x509.MarshalPKIXPublicKey(&pk)
		return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	}()
	cases := []struct {
		name, want string
		enc        string
		f          func(c *Config)
	}{
		{"installer-reserved admin", "admin user", EncNone, func(c *Config) { c.AdminUser = "admin" }},
		{"root", "admin user", EncNone, func(c *Config) { c.AdminUser = "root" }},
		{"operator", "admin user", EncNone, func(c *Config) { c.AdminUser = "operator" }},
		{"agentboxd service uid", "admin user", EncNone, func(c *Config) { c.AdminUser = "agentbox" }},
		{"agent namespace", "admin user", EncNone, func(c *Config) { c.AdminUser = "ag-claude" }},
		{"image account", "admin user", EncNone, func(c *Config) { c.AdminUser = "_apt" }},
		{"image group clock", "admin user", EncNone, func(c *Config) { c.AdminUser = "clock" }},
		{"image group rdma", "admin user", EncNone, func(c *Config) { c.AdminUser = "rdma" }},
		{"amd64 image user usbmux", "admin user", EncNone, func(c *Config) { c.AdminUser = "usbmux" }},
		{"33-char user", "admin user", EncNone, func(c *Config) { c.AdminUser = strings.Repeat("a", 33) }},
		{"serial with space (shell/YAML injection)", "disk serial", EncNone, func(c *Config) { c.DiskSerial = "S4EV 123; rm -rf /" }},
		{"ssh-from with shell (injection)", "--ssh-from", EncNone, func(c *Config) { c.SSHFrom = []string{"10.0.0.0/8'; reboot; '"} }},
		{"ssh-from overlapping", "--ssh-from", EncNone, func(c *Config) { c.SSHFrom = []string{"10.0.0.0/8", "10.1.0.0/16"} }},
		{"serial with quote", "disk serial", EncNone, func(c *Config) { c.DiskSerial = "S4EV'x" }},
		{"serial with newline", "disk serial", EncNone, func(c *Config) { c.DiskSerial = "S4EV\n" }},
		{"empty serial", "disk serial", EncNone, func(c *Config) { c.DiskSerial = "" }},
		{"quote in ssh comment", "ssh key", EncNone, func(c *Config) { c.SSHKeys = []string{"ssh-ed25519 AAAA you'@laptop"} }},
		{"truncated ed25519 blob", "ssh key", EncNone, func(c *Config) { c.SSHKeys = []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGb9c8 you@laptop"} }},
		{"no ssh keys", "--ssh-key", EncNone, func(c *Config) { c.SSHKeys = nil }},
		{"plain password", "password hash", EncNone, func(c *Config) { c.AdminPasswordHash = "hunter2" }},
		{"impossible hash tail", "password hash", EncNone, func(c *Config) { c.AdminPasswordHash = "$6$rounds=100000$saltsalt$" + strings.Repeat("a", 86) }},
		{"sha512 default 5000 rounds (openssl passwd -6)", "password hash", EncNone, func(c *Config) {
			c.AdminPasswordHash = "$6$gatesalt$99DJkr0wJ/juWOF.HTWbZKxnJZDHcqny21RN4rr0J/sQAT2xWQXUZNuVdpZn40q3ER/GB5wyxlM0bBcOhZvR8."
		}},
		{"sha512 99999 rounds", "password hash", EncNone, func(c *Config) { c.AdminPasswordHash = "$6$rounds=99999$saltsalt$" + strings.Repeat("a", 85) + "0" }},
		{"sha512 rounds with a leading zero", "password hash", EncNone, func(c *Config) { c.AdminPasswordHash = "$6$rounds=0100000$saltsalt$" + strings.Repeat("a", 85) + "0" }},
		{"md5-crypt", "password hash", EncNone, func(c *Config) { c.AdminPasswordHash = "$1$saltsalt$qjXMvbEw8oaL.CzflDugX/" }},
		{"yescrypt hash cut short", "password hash", EncNone, func(c *Config) {
			c.AdminPasswordHash = "$y$j9T$agentboxgatesalt0000$nVjZH1ZaNBH.vEdKjhLQLZVUy6bJDJKQOxEO8qRil2"
		}},
		{"yescrypt without params", "password hash", EncNone, func(c *Config) {
			c.AdminPasswordHash = "$y$$agentboxgatesalt0000$nVjZH1ZaNBH.vEdKjhLQLZVUy6bJDJKQOxEO8qRil23"
		}},
		{"newline after the hash", "password hash", EncNone, func(c *Config) { c.AdminPasswordHash += "\n" }},
		{"http release", "release url", EncNone, func(c *Config) { c.ReleaseURL = "http://releases.example.com/a.tgz" }},
		{"query in release url", "release url", EncNone, func(c *Config) { c.ReleaseURL = "https://x.example.com/a.tgz?x=1&y=$(id)" }},
		{"vm release url without --dev", "release url", EncNone, func(c *Config) { c.ReleaseURL = "http://10.0.2.2:7600/a.tgz" }},
		{"--dev http url off the vm host", "release url", EncNone, func(c *Config) { c.Dev, c.ReleaseURL = true, "http://192.168.1.5:7600/a.tgz" }},
		{"--dev url without port", "release url", EncNone, func(c *Config) { c.Dev, c.ReleaseURL = true, "http://10.0.2.2/a.tgz" }},
		{"--dev url with query", "release url", EncNone, func(c *Config) { c.Dev, c.ReleaseURL = true, "http://10.0.2.2:7600/a.tgz?$(id)" }},
		{"release port 0", "release url", EncNone, func(c *Config) { c.ReleaseURL = "https://releases.example.com:0/a.tgz" }},
		{"release port 70000", "release url", EncNone, func(c *Config) { c.ReleaseURL = "https://releases.example.com:70000/a.tgz" }},
		{"--dev url port 99999", "release url", EncNone, func(c *Config) { c.Dev, c.ReleaseURL = true, "http://10.0.2.2:99999/a.tgz" }},
		{"no release sha256", "release sha256", EncNone, func(c *Config) { c.ReleaseSHA256 = "" }},
		{"short release sha256", "release sha256", EncNone, func(c *Config) { c.ReleaseSHA256 = testSHA[:63] }},
		{"release sha256 with shell", "release sha256", EncNone, func(c *Config) { c.ReleaseSHA256 = testSHA[:60] + "$(x)" }},
		{"tang without thp", "tang thp", EncTPM2Tang, func(c *Config) { c.TangThp = "" }},
		{"tang url with quote", "tang url", EncTPM2Tang, func(c *Config) { c.TangURL = "http://x'y" }},
		{"tang hostname", "tang url", EncTPM2Tang, func(c *Config) { c.TangURL = "http://tang.lan:7500" }},
		{"tang https", "tang url", EncTPM2Tang, func(c *Config) { c.TangURL = "https://192.168.1.10" }},
		{"tang public ip", "tang url", EncTPM2Tang, func(c *Config) { c.TangURL = "http://203.0.113.5:7500" }},
		{"tang bad ip", "tang url", EncTPM2Tang, func(c *Config) { c.TangURL = "http://999.1.1.1" }},
		{"tang port 0", "tang url", EncTPM2Tang, func(c *Config) { c.TangURL = "http://192.168.1.10:0/tang" }},
		{"tang port 65536", "tang url", EncTPM2Tang, func(c *Config) { c.TangURL = "http://192.168.1.10:65536" }},
		{"tang url in tpm2 mode", "tang url/thp", EncTPM2, func(c *Config) { c.TangURL = "http://192.168.1.10" }},
		{"bad encryption", "encryption", EncNone, func(c *Config) { c.Encryption = "luks" }},
		{"bad boot", "boot", EncNone, func(c *Config) { c.Boot = "efi" }},
		{"uppercase hostname", "hostname", EncNone, func(c *Config) { c.Hostname = "AgentBox" }},
		{"no recovery key", "--recovery-pub is required", EncTPM2, func(c *Config) { c.RecoveryPubPEM = nil }},
		{"recovery key in none mode", "--recovery-pub only applies", EncNone, func(c *Config) { c.RecoveryPubPEM = []byte("x") }},
		{"e=1 recovery key", "e=65537", EncTPM2, func(c *Config) { c.RecoveryPubPEM = weak }},
		{"bad minisign key", "minisign", EncNone, func(c *Config) { c.MinisignPubKey = "RWabc" }},
		{"minisign key not Ed25519", "minisign", EncNone, func(c *Config) { c.MinisignPubKey = "RWzz" + strings.Repeat("z", 52) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig(t, tc.enc, "uefi")
			tc.f(c)
			err := c.Validate()
			// errors.Join separates errors with "\n": exactly one error, naming the mutated field
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "\n") {
				t.Fatalf("want exactly one %q error, got %v", tc.want, err)
			}
		})
	}
}

// TestSSHFrom runs the rendered ssh-from line under dash: the file holds the parsed prefixes, and no flag writes none
// (fw.DefaultSSHFrom applies).
func TestSSHFrom(t *testing.T) {
	if _, err := exec.LookPath("dash"); err != nil {
		t.Skip("needs dash")
	}
	c := validConfig(t, EncNone, "uefi")
	ud, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ud), "ssh-from") {
		t.Error("a seed without --ssh-from writes an ssh-from file")
	}
	c.SSHFrom = []string{"192.168.1.7/24", "fd00::/8", "10.0.2.2/32"}
	ud, err = Render(c)
	if err != nil {
		t.Fatal(err)
	}
	var line string
	for _, l := range strings.Split(string(ud), "\n") {
		if strings.Contains(l, "/etc/agentbox/ssh-from") {
			line = strings.TrimSpace(l)
		}
	}
	root := t.TempDir()
	if out, err := exec.Command("dash", "-euc", strings.ReplaceAll(line, "/mnt/new", root)).CombinedOutput(); err != nil {
		t.Fatalf("%q: %v: %s", line, err, out)
	}
	b, err := os.ReadFile(filepath.Join(root, "etc", "agentbox", "ssh-from"))
	if err != nil || string(b) != "192.168.1.0/24\nfd00::/8\n10.0.2.2/32\n" {
		t.Errorf("ssh-from file %q, %v", b, err)
	}
}

func TestValidateAccepts(t *testing.T) {
	for _, s := range []string{"QM00001", "QEMU_NVMe_Ctrl_QM00001_1", "WDC_WD10EZEX-08WN4A0_WD-WCC6Y1234567", "Generic_Flash_Disk_FBA5D7A1-0:0"} {
		c := validConfig(t, EncNone, "uefi")
		c.DiskSerial = s
		if err := c.Validate(); err != nil {
			t.Errorf("serial %q: %v", s, err)
		}
	}
	for _, h := range []string{ // libxcrypt 4.5.1 crypt("x"): sha512 at the floor, and a non-default yescrypt cost
		"$6$rounds=100000$gatesalt$PJzNps4L0wTr6EuAOurqVB/VEVeGKeSEpNIR4BLw3eJyf2vEAyw2ETSqg5VBL1fNrlHAQO7p7ZzCYTHME6iRp1",
		"$y$jFT$0123456789abcdef$DYe.xGroU4Z4Ik0GuQULaEeoxCOS7MfKcL.WEiOxeB/",
	} {
		c := validConfig(t, EncNone, "uefi")
		c.AdminPasswordHash = h
		if err := c.Validate(); err != nil {
			t.Errorf("hash %q: %v", h, err)
		}
	}
	for _, u := range []string{"boxadmin", "ubuntu", "owner"} {
		c := validConfig(t, EncNone, "uefi")
		c.AdminUser = u
		if err := c.Validate(); err != nil {
			t.Errorf("user %q: %v", u, err)
		}
	}
	for _, u := range []string{"https://releases.example.com/a.tgz", "http://10.0.2.2:7600/agentbox-0.0.1-gate.tgz",
		"https://releases.example.com:65535/a.tgz", "http://10.0.2.2:1/a.tgz"} {
		c := validConfig(t, EncNone, "uefi")
		c.Dev, c.ReleaseURL = true, u
		if err := c.Validate(); err != nil {
			t.Errorf("--dev release url %q: %v", u, err)
		}
	}
	for _, u := range []string{"http://192.168.1.10", "http://192.168.1.10:1/tang", "http://192.168.1.10:65535"} {
		c := validConfig(t, EncTPM2Tang, "uefi")
		c.TangURL = u
		if err := c.Validate(); err != nil {
			t.Errorf("tang url %q: %v", u, err)
		}
	}
}

// TestDiskGuard runs the rendered early-commands[0] under dash against a fake sysfs, /dev/disk/by-id and udevadm.
func TestDiskGuard(t *testing.T) {
	dash, err := exec.LookPath("dash")
	if err != nil {
		t.Skip("dash not installed")
	}
	v, err := validConfig(t, EncNone, "uefi").view()
	if err != nil {
		t.Fatal(err)
	}
	const S = "Samsung_SSD_870_EVO_500GB_S4EVNX0N123456"
	run := func(t *testing.T, disks map[string]string, links map[string]string) error {
		root := t.TempDir()
		for _, d := range []string{"bin", "block", "byid", "class", "devs", "serials"} {
			os.MkdirAll(filepath.Join(root, d), 0o755)
		}
		os.WriteFile(filepath.Join(root, "bin/udevadm"), []byte("#!/bin/sh\n[ \"$1\" = settle ] && exit 0\nfor a; do p=$a; done\nf=\""+root+"/serials/${p##*/}\"; [ -f \"$f\" ] && cat \"$f\"; exit 0\n"), 0o755)
		for d, s := range disks {
			os.MkdirAll(filepath.Join(root, "block", d), 0o755)
			os.WriteFile(filepath.Join(root, "serials", d), []byte(s), 0o644)
			os.MkdirAll(filepath.Join(root, "devs", d, d+"p1"), 0o755)
			os.WriteFile(filepath.Join(root, "devs", d, d+"p1", "partition"), nil, 0o644)
			os.Symlink(filepath.Join(root, "devs", d), filepath.Join(root, "class", d))
			os.Symlink(filepath.Join(root, "devs", d, d+"p1"), filepath.Join(root, "class", d+"p1"))
		}
		for name, target := range links {
			os.WriteFile(filepath.Join(root, target), nil, 0o644)
			os.Symlink(filepath.Join(root, target), filepath.Join(root, "byid", name))
		}
		cmd := strings.NewReplacer("/sys/block/", root+"/block/", "/dev/disk/by-id/", root+"/byid/", "/sys/class/block/", root+"/class/").Replace(v.DiskGuardCmd)
		c := exec.Command(dash, "-c", cmd)
		c.Env = append(os.Environ(), "PATH="+root+"/bin:"+os.Getenv("PATH"))
		return c.Run()
	}
	ok := map[string]string{"nvme-" + S: "nvme0n1", "nvme-" + S + "-part1": "nvme0n1p1"}
	if err := run(t, map[string]string{"nvme0n1": S, "vdb": ""}, ok); err != nil {
		t.Errorf("unique disk rejected: %v", err)
	}
	if run(t, map[string]string{"nvme0n1": "other"}, nil) == nil {
		t.Error("no matching disk accepted")
	}
	if run(t, map[string]string{"nvme0n1": S, "sda": S}, ok) == nil {
		t.Error("duplicate ID_SERIAL accepted")
	}
	collide := map[string]string{"nvme-" + S: "nvme0n1", "usb-X_" + S + "-0:0": "sdb"}
	if run(t, map[string]string{"nvme0n1": S, "sdb": "usb"}, collide) == nil {
		t.Error("by-id substring collision accepted")
	}
}

// TestGrub09 runs the rendered 09_agentbox under dash: oldest generation first, numeric fallback, hostile names skipped.
func TestGrub09(t *testing.T) {
	dash, err := exec.LookPath("dash")
	if err != nil {
		t.Skip("dash not installed")
	}
	out, err := Render(validConfig(t, EncNone, "uefi"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)<<'G9'\n(.*?)\n      G9\n`).FindSubmatch(out)
	if m == nil {
		t.Fatal("09_agentbox heredoc not found")
	}
	script := regexp.MustCompile(`(?m)^      `).ReplaceAll(m[1], nil)
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "bin"), 0o755)
	os.WriteFile(filepath.Join(root, "bin/grub-probe"), []byte("#!/bin/sh\necho UUID\n"), 0o755)
	for _, g := range []string{"gen-1", "gen-2", "gen-10", "genX"} {
		for _, k := range []string{"7.0.0-43-generic", "7.0.0-44-generic", "bad'name"} {
			d := filepath.Join(root, "bp/agentbox/gens", g)
			os.MkdirAll(d, 0o755)
			os.WriteFile(filepath.Join(d, "vmlinuz-"+k), nil, 0o644)
			os.WriteFile(filepath.Join(d, "initrd.img-"+k), nil, 0o644)
		}
	}
	script = bytes.Replace(script, []byte("BP=/bootpart"), []byte("BP="+root+"/bp"), 1)
	c := exec.Command(dash, "-c", string(script))
	c.Env = append(os.Environ(), "PATH="+root+"/bin:"+os.Getenv("PATH"))
	got, err := c.Output()
	if err != nil {
		t.Fatal(err)
	}
	ids := regexp.MustCompile(`--id '(agentbox-[^']+)'`).FindAllSubmatch(got, -1)
	var order []string
	for _, id := range ids {
		order = append(order, string(id[1]))
	}
	want := "agentbox-gen-1-7.0.0-44-generic agentbox-gen-1-7.0.0-43-generic agentbox-gen-2-7.0.0-44-generic agentbox-gen-2-7.0.0-43-generic agentbox-gen-10-7.0.0-44-generic agentbox-gen-10-7.0.0-43-generic"
	if strings.Join(order, " ") != want {
		t.Fatalf("entries %v, want %s", order, want)
	}
	if !bytes.Contains(got, []byte(`if [ "${saved_entry}" = "agentbox-gen-10-7.0.0-43-generic" ]; then set fallback=5; fi; fi`)) {
		t.Fatalf("missing numeric fallback for index 5:\n%s", got)
	}
	if bytes.Contains(got, []byte("rd.luks.uuid")) || bytes.Contains(got, []byte("set default")) {
		t.Fatalf("no crypttab and no committed file: want neither rd.luks.uuid nor a default:\n%s", got)
	}

	// encrypted modes: rd.luks.uuid from the croot crypttab line; the committed file names the empty-grubenv default
	os.WriteFile(filepath.Join(root, "crypttab"), []byte("croot UUID=40c5699d-54cf-46bb-a07e-4adf9e3629c7 none luks,x-initrd.attach,timeout=300s\n"), 0o644)
	os.WriteFile(filepath.Join(root, "bp/agentbox/committed"), []byte("agentbox-gen-2-7.0.0-44-generic\n"), 0o644)
	script = bytes.Replace(script, []byte("/etc/crypttab"), []byte(root+"/crypttab"), -1)
	c = exec.Command(dash, "-c", string(script))
	c.Env = append(os.Environ(), "PATH="+root+"/bin:"+os.Getenv("PATH"))
	if got, err = c.Output(); err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(got, []byte(" rootflags=subvol=@")); n != 6 || bytes.Count(got, []byte(" rd.luks.uuid=40c5699d-54cf-46bb-a07e-4adf9e3629c7 rootflags=subvol=@")) != n {
		t.Fatalf("every entry needs rd.luks.uuid:\n%s", got)
	}
	if !bytes.HasSuffix(got, []byte(`if [ -z "${boot_once}" ]; then if [ -z "${saved_entry}" ]; then set default="agentbox-gen-2-7.0.0-44-generic"; fi; fi`+"\n")) {
		t.Fatalf("missing the committed fallback:\n%s", got)
	}
	for _, bad := range []string{"", "Ubuntu\n", "agentbox-gen-2-7.0'x\n"} {
		os.WriteFile(filepath.Join(root, "bp/agentbox/committed"), []byte(bad), 0o644)
		c = exec.Command(dash, "-c", string(script))
		c.Env = append(os.Environ(), "PATH="+root+"/bin:"+os.Getenv("PATH"))
		if out, err := c.Output(); err == nil {
			t.Errorf("committed %q accepted:\n%s", bad, out)
		}
	}
}

// TestBootDeadline runs the rendered agentbox-boot-deadline under dash: it reboots unless the booted entry is
// saved_entry or, with an empty grubenv, the committed one.
func TestBootDeadline(t *testing.T) {
	dash, err := exec.LookPath("dash")
	if err != nil {
		t.Skip("dash not installed")
	}
	out, err := Render(validConfig(t, EncTPM2, "uefi"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)<<'BD'\n(.*?)\n      BD\n`).FindSubmatch(out)
	if m == nil {
		t.Fatal("agentbox-boot-deadline heredoc not found")
	}
	root := t.TempDir()
	script := regexp.MustCompile(`(?m)^      `).ReplaceAll(m[1], nil)
	script = bytes.ReplaceAll(script, []byte("/boot/grub/grubenv"), []byte(root+"/grubenv"))
	script = bytes.ReplaceAll(script, []byte("/bootpart/agentbox/committed"), []byte(root+"/committed"))
	os.MkdirAll(filepath.Join(root, "bin"), 0o755)
	for name, body := range map[string]string{
		"findmnt":   "echo /@gen-2",
		"uname":     "echo 7.0.0-44-generic",
		"systemctl": "echo \"$*\" > " + root + "/rebooted",
	} {
		os.WriteFile(filepath.Join(root, "bin", name), []byte("#!/bin/sh\n"+body+"\n"), 0o755)
	}
	for _, tc := range []struct {
		name, grubenv, committed string
		reboot                   bool
	}{
		{"committed", "saved_entry=agentbox-gen-2-7.0.0-44-generic\n", "agentbox-gen-2-7.0.0-44-generic\n", false},
		{"trial", "saved_entry=agentbox-gen-1-7.0.0-43-generic\n", "agentbox-gen-1-7.0.0-43-generic\n", true},
		{"other kernel of the committed generation", "saved_entry=agentbox-gen-2-7.0.0-43-generic\n", "agentbox-gen-2-7.0.0-43-generic\n", true},
		{"empty grubenv, booted the committed one", "", "agentbox-gen-2-7.0.0-44-generic\n", false},
		{"empty grubenv, no committed file", "", "", true},
	} {
		os.Remove(filepath.Join(root, "rebooted"))
		os.Remove(filepath.Join(root, "committed"))
		os.WriteFile(filepath.Join(root, "grubenv"), []byte("# GRUB Environment Block\n"+tc.grubenv+"#####\n"), 0o644)
		if tc.committed != "" {
			os.WriteFile(filepath.Join(root, "committed"), []byte(tc.committed), 0o644)
		}
		c := exec.Command(dash, "-c", string(script))
		c.Env = append(os.Environ(), "PATH="+root+"/bin:"+os.Getenv("PATH"), "AGENTBOX_BOOT_DEADLINE_SEC=0")
		c.Run()
		got, err := os.ReadFile(filepath.Join(root, "rebooted"))
		if rebooted := err == nil; rebooted != tc.reboot || (rebooted && string(got) != "reboot --force\n") {
			t.Errorf("%s: rebooted=%v (%q), want %v", tc.name, rebooted, got, tc.reboot)
		}
	}
}

func TestWriteNoCloudAndISO(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "seed")
	c := validConfig(t, EncNone, "uefi")
	if err := WriteNoCloud(c, dir, time.Unix(1762800000, 0)); err != nil {
		t.Fatal(err)
	}
	md, _ := os.ReadFile(filepath.Join(dir, "meta-data"))
	if string(md) != "instance-id: agentbox-agentbox-1762800000\n" {
		t.Fatalf("meta-data = %q", md)
	}
	for _, p := range []string{dir, filepath.Join(dir, "user-data")} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s must be private, got %v %v", p, fi.Mode(), err)
		}
	}
	x, err := exec.LookPath("xorriso")
	if err != nil {
		t.Skip("xorriso not installed")
	}
	// xorriso creates its output under the umask: this wrapper fails unless xorriso wrote into a file already 0600
	bin := t.TempDir()
	shim := "#!/bin/sh\numask 022\n'" + x + "' \"$@\" || exit\nfor a; do [ \"$p\" = -o ] && o=$a; p=$a; done\n" +
		"case $(ls -l \"$o\") in -rw-------*) ;; *) ls -l \"$o\" >&2; exit 3 ;; esac\n"
	if err := os.WriteFile(filepath.Join(bin, "xorriso"), []byte(shim), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	iso := filepath.Join(filepath.Dir(dir), "seed.iso") // README layout: --out seed --iso seed.iso
	if err := os.WriteFile(iso, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	old, err := os.Open(iso) // a reader who opened an earlier, world-readable seed.iso
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	if err := BuildCidataISO(t.TempDir(), iso); err == nil {
		t.Fatal("BuildCidataISO without user-data succeeded")
	}
	if b, _ := os.ReadFile(iso); string(b) != "old" {
		t.Fatalf("a failed build replaced the earlier ISO (%d bytes)", len(b))
	}
	if err := BuildCidataISO(dir, iso); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(iso); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Fatalf("iso mode %v, want 0600", fi.Mode())
	}
	if b, _ := io.ReadAll(old); string(b) != "old" {
		t.Fatalf("the build wrote %d bytes into the inode an earlier reader holds open", len(b))
	}
	if ents, _ := os.ReadDir(filepath.Dir(dir)); len(ents) != 2 {
		t.Fatalf("temp file left next to the ISO: %v", ents)
	}
	link := filepath.Join(t.TempDir(), "seed.iso")
	if err := os.Symlink(iso, link); err != nil {
		t.Fatal(err)
	}
	if err := BuildCidataISO(dir, link); err == nil {
		t.Fatal("BuildCidataISO replaced a symlink instead of refusing it")
	}
	out, _ := exec.Command(x, "-indev", iso, "-pvd_info", "-find", "/", "-type", "f").CombinedOutput()
	for _, w := range []string{"Volume Id    : cidata", "'/user-data'", "'/meta-data'"} {
		if !bytes.Contains(out, []byte(w)) {
			t.Fatalf("iso missing %q:\n%s", w, out)
		}
	}
}

// TestInstallerOpenSSLLine runs the seed's own openssl line and opens the result with `agentbox recovery decrypt`'s code.
func TestInstallerOpenSSLLine(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not installed")
	}
	if v, _ := exec.Command(openssl, "version").Output(); bytes.HasPrefix(v, []byte("LibreSSL")) {
		t.Skip("LibreSSL lacks OAEP-SHA256")
	}
	dir := t.TempDir()
	priv, pub, err := recovery.GenerateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	c := validConfig(t, EncTPM2, "uefi")
	c.RecoveryPubPEM, _ = os.ReadFile(pub)
	out, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(out, []byte("openssl pkeyutl"))
	j := bytes.Index(out[i:], []byte("recovery.bin"))
	if i < 0 || j < 0 {
		t.Fatal("openssl line not found")
	}
	key, bin := filepath.Join(dir, "luks.key"), filepath.Join(dir, "recovery.bin")
	secret := []byte("012345678901234567890123456789012345678901234567") // installer keyfile: 48 digits, no newline
	os.WriteFile(key, secret, 0o600)
	line := strings.NewReplacer("/run/agentbox-recovery.pub", pub, "/run/agentbox-luks.key", key,
		"/mnt/new/bootpart/agentbox/recovery.bin", bin).Replace(string(out[i : i+j+len("recovery.bin")]))
	if msg, err := exec.Command("sh", "-c", line).CombinedOutput(); err != nil {
		t.Fatalf("installer openssl line failed: %v: %s", err, msg) // fail, don't skip
	}
	ct, _ := os.ReadFile(bin)
	privPEM, _ := os.ReadFile(priv)
	if got, err := recovery.Decrypt(privPEM, ct); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("recovery decrypt can't open the installer's recovery.bin: %v", err)
	}
}

func sshRSALine(t *testing.T, bits int) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	str := func(b []byte) []byte {
		l := make([]byte, 4)
		binary.BigEndian.PutUint32(l, uint32(len(b)))
		return append(l, b...)
	}
	mpint := func(b []byte) []byte {
		if len(b) > 0 && b[0]&0x80 != 0 {
			b = append([]byte{0}, b...)
		}
		return str(b)
	}
	blob := append(append(str([]byte("ssh-rsa")), mpint(big.NewInt(int64(k.E)).Bytes())...), mpint(k.N.Bytes())...)
	return "ssh-rsa " + base64.StdEncoding.EncodeToString(blob) + " you@laptop"
}

func TestSSHRSAKeySize(t *testing.T) {
	for _, tc := range []struct {
		bits int
		ok   bool
	}{{2048, false}, {3072, true}} {
		c := validConfig(t, EncNone, "uefi")
		c.SSHKeys = []string{sshRSALine(t, tc.bits)}
		if err := c.Validate(); (err == nil) != tc.ok {
			t.Errorf("ssh-rsa %d bits: err=%v, want ok=%v", tc.bits, err, tc.ok)
		}
	}
}

// TestRenderedSeedsVerify runs hack/verify-seed.py (real YAML parse, structure asserts, dash -n on every script) on all six seeds.
func TestRenderedSeedsVerify(t *testing.T) {
	var cmd []string
	if uv, err := exec.LookPath("uv"); err == nil {
		cmd = []string{uv, "run", "-q", "--with", "pyyaml", "python3", "-I"}
	} else if py, err := exec.LookPath("python3"); err == nil && exec.Command(py, "-c", "import yaml").Run() == nil {
		cmd = []string{py, "-I"}
	}
	if _, err := exec.LookPath("dash"); err != nil || cmd == nil {
		if os.Getenv("CI") != "" {
			t.Fatal("CI needs dash plus uv, or python3 with pyyaml, to verify seeds")
		}
		t.Skip("needs dash plus uv, or python3 with pyyaml")
	}
	for _, enc := range []string{EncTPM2Tang, EncTPM2, EncNone} {
		for _, boot := range []string{"uefi", "bios"} {
			dir := t.TempDir()
			c := validConfig(t, enc, boot)
			if enc == EncNone {
				c.SSHFrom = []string{"192.168.1.0/24", "fd00::/8"}
			}
			if err := WriteNoCloud(c, dir, time.Unix(0, 0)); err != nil {
				t.Fatal(err)
			}
			args := append(append([]string{}, cmd[1:]...), filepath.Join("..", "..", "hack", "verify-seed.py"), filepath.Join(dir, "user-data"))
			if out, err := exec.Command(cmd[0], args...).CombinedOutput(); err != nil {
				t.Errorf("%s/%s: %v\n%s", enc, boot, err, out)
			}
		}
	}
}

// TestDracutHardware runs the rendered late-commands lines that record the root disk's driver chain and the box's
// watchdog driver under dash -eu, against a fake sysfs and fake modprobe and modinfo.
func TestDracutHardware(t *testing.T) {
	dash, err := exec.LookPath("dash")
	if err != nil {
		t.Skip("dash not installed")
	}
	out, err := Render(validConfig(t, EncNone, "uefi"))
	if err != nil {
		t.Fatal(err)
	}
	const conf = "/mnt/new/etc/dracut.conf.d/90-agentbox.conf"
	m := regexp.MustCompile(`(?s)\n      (DRV=; p=.*?` + regexp.QuoteMeta(conf) + `)\n`).FindSubmatch(out)
	if m == nil {
		t.Fatal("driver chain and watchdog lines not found")
	}
	run := func(t *testing.T, watchdog bool) string {
		root, err := filepath.EvalSymlinks(t.TempDir()) // readlink -f must not leave the fake root (macOS /var -> /private/var)
		if err != nil {
			t.Fatal(err)
		}
		// nvme behind a PCIe root port: the port's built-in driver has a module link but no initstate, and must not be recorded
		port := root + "/sys/devices/pci0000:00/0000:00:1c.0"
		dev := port + "/0000:01:00.0"
		for _, d := range []string{"bin", "dev", dev + "/nvme/nvme0/nvme0n1/nvme0n1p3", "sys/class/block", "sys/bus/pci/drivers/nvme", "sys/module/nvme",
			"sys/bus/pci/drivers/pcieport", "sys/module/pcieportdrv", "sys/bus/acpi/devices/QEMU0002:00", "sys/bus/pci/devices/0000:01:00.0",
			"sys/bus/pci/devices/0000:00:04.0"} {
			os.MkdirAll(filepath.Join(root, strings.TrimPrefix(d, root)), 0o755)
		}
		os.WriteFile(root+"/dev/nvme0n1p3", nil, 0o644)
		os.WriteFile(root+"/sys/module/nvme/initstate", []byte("live\n"), 0o644)
		os.Symlink(dev+"/nvme/nvme0/nvme0n1/nvme0n1p3", root+"/sys/class/block/nvme0n1p3")
		os.Symlink(root+"/sys/bus/pci/drivers/nvme", dev+"/driver")
		os.Symlink(root+"/sys/module/nvme", root+"/sys/bus/pci/drivers/nvme/module")
		os.Symlink(root+"/sys/bus/pci/drivers/pcieport", port+"/driver")
		os.Symlink(root+"/sys/module/pcieportdrv", root+"/sys/bus/pci/drivers/pcieport/module")
		os.WriteFile(root+"/sys/bus/acpi/devices/QEMU0002:00/modalias", []byte("acpi:QEMU0002:\n"), 0o644) // sorts first and resolves to nothing
		os.WriteFile(root+"/sys/bus/pci/devices/0000:01:00.0/modalias", []byte("pci:v00001B36d00000010sv00001AF4sd00001100bc01sc08i02\n"), 0o644)
		if watchdog {
			os.WriteFile(root+"/sys/bus/pci/devices/0000:00:04.0/modalias", []byte("pci:v00008086d000025ABsv00001AF4sd00001100bc08sc80i00\n"), 0o644)
		}
		os.WriteFile(root+"/bin/modprobe", []byte("#!/bin/sh\ncase $2 in pci:v00008086d000025AB*) echo i6300esb ;; pci:v00001B36d00000010*) echo nvme ;; *) exit 1 ;; esac\n"), 0o755)
		os.WriteFile(root+"/bin/modinfo", []byte("#!/bin/sh\nshift 2; for m; do case $m in nvme) echo /lib/modules/7.0.0-43-generic/kernel/drivers/nvme/host/nvme.ko.zst ;;\n"+
			"i6300esb) echo /lib/modules/7.0.0-43-generic/kernel/drivers/watchdog/i6300esb.ko.zst ;; *) exit 1 ;; esac; done\n"), 0o755)
		script := strings.NewReplacer("/sys/", root+"/sys/", conf, root+"/90-agentbox.conf").Replace(string(m[1]))
		c := exec.Command(dash, "-euc", script)
		c.Env = append(os.Environ(), "PATH="+root+"/bin:"+os.Getenv("PATH"), "DEV="+root+"/dev/nvme0n1p3")
		if msg, err := c.CombinedOutput(); err != nil {
			t.Fatalf("%v: %s", err, msg)
		}
		b, _ := os.ReadFile(root + "/90-agentbox.conf")
		return string(b)
	}
	for _, tc := range []struct {
		watchdog bool
		want     string
	}{{true, `force_drivers+=" i6300esb "`}, {false, `force_drivers+=" softdog "`}} {
		got := run(t, tc.watchdog)
		for _, w := range []string{`hostonly="yes"`, `add_dracutmodules+=" btrfs "`, `add_drivers+=" nvme "`, tc.want} {
			if !strings.Contains(got, w+"\n") {
				t.Errorf("watchdog device %v: 90-agentbox.conf lacks %q:\n%s", tc.watchdog, w, got)
			}
		}
	}
}

// TestKernelSwap runs the rendered late-commands lines that replace the installer's leftover linux-image-unsigned-K
// with the signed linux-image-K under dash -eu, with a fake chroot: one apt call for every installed unsigned image,
// none (and no failure) when there is none, and all of it before the initrds are rebuilt.
func TestKernelSwap(t *testing.T) {
	dash, err := exec.LookPath("dash")
	if err != nil {
		t.Skip("dash not installed")
	}
	out, err := Render(validConfig(t, EncTPM2, "uefi"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimPrefix(l, "      "); strings.HasPrefix(l, "U=$(chroot /mnt/new dpkg-query ") || strings.HasPrefix(l, `[ -z "$U" ] || `) {
			lines = append(lines, l)
		}
	}
	if len(lines) != 2 {
		t.Fatalf("kernel swap lines not found: %q", lines)
	}
	if i, j := strings.Index(s, lines[1]), strings.Index(s, "chroot /mnt/new dracut -f --regenerate-all"); j < 0 || i > j {
		t.Fatal("the kernel swap must run before dracut --regenerate-all")
	}
	bin := t.TempDir()
	log := filepath.Join(bin, "apt.log")
	// dpkg-query -W -f '${db:Status-Abbrev}${Package}\n' prints "ii " for installed, "rc " for removed with config files
	os.WriteFile(filepath.Join(bin, "chroot"), []byte(`#!/bin/sh
[ "$1" = /mnt/new ] || exit 1; shift
case $1 in
dpkg-query) [ -n "$PKGS" ] || { echo "dpkg-query: no packages found matching $5" >&2; exit 1; }; printf "$PKGS" ;;
env) shift; echo "$*" >> "$LOG" ;;
*) exit 1 ;;
esac
`), 0o755)
	for _, tc := range []struct{ pkgs, want string }{
		{"ii linux-image-unsigned-7.0.0-30-generic\\nrc linux-image-unsigned-6.19.0-5-generic\\n",
			"DEBIAN_FRONTEND=noninteractive apt-get install -y linux-image-7.0.0-30-generic\n"},
		{"ii linux-image-unsigned-7.0.0-30-generic\\nii linux-image-unsigned-7.0.0-43-generic\\n",
			"DEBIAN_FRONTEND=noninteractive apt-get install -y linux-image-7.0.0-30-generic linux-image-7.0.0-43-generic\n"},
		{"", ""},
	} {
		os.Remove(log)
		c := exec.Command(dash, "-euc", strings.Join(lines, "\n"))
		c.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "PKGS="+tc.pkgs, "LOG="+log)
		if msg, err := c.CombinedOutput(); err != nil {
			t.Fatalf("%q: %v: %s", tc.pkgs, err, msg)
		}
		if got, _ := os.ReadFile(log); string(got) != tc.want {
			t.Errorf("%q: apt ran %q, want %q", tc.pkgs, got, tc.want)
		}
	}
}
