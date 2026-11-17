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

func testSSHKey(t *testing.T) string {
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

func validConfig(t *testing.T, enc, boot string) *Config {
	t.Helper()
	c := &Config{
		Hostname:          "agentbox",
		AdminUser:         "boxadmin",
		AdminPasswordHash: "$6$saltsalt$" + strings.Repeat("a", 85) + "0",
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

func TestRenderModes(t *testing.T) {
	encWant := map[string][]string{
		EncTPM2Tang: {"keyfile: /run/agentbox-luks.key, options: [luks, x-initrd.attach, timeout=300s]}",
			"{type: format, id: froot, volume: croot, fstype: btrfs}", "ip=dhcp rd.neednet=1",
			`sss '{"pins":{"tang":[{"thp":"_OsIk0T-E2l6qjfdDiwVmidoZjA","url":"http://192.168.1.10:7500"}],"tpm2":{}},"t":2}'`,
			"clevis-dracut", "dracut -f --regenerate-all", "head -c 48", "shred -u /run/agentbox-luks.key", "-pkeyopt rsa_oaep_md:sha256",
			"test -c /dev/tpmrm0"},
		EncTPM2: {"{type: format, id: froot, volume: croot, fstype: btrfs}", ` tpm2 '{}'`, "clevis-dracut",
			"shred -u /run/agentbox-luks.key", "-pkeyopt rsa_oaep_md:sha256", "test -c /dev/tpmrm0"},
		EncNone: {"{type: format, id: froot, volume: proot, fstype: btrfs}"},
	}
	encAvoid := map[string][]string{
		EncTPM2Tang: {"volume: proot, fstype: btrfs", "pcr_ids", "apt-get install", "head -c 64"},
		EncTPM2:     {"volume: proot, fstype: btrfs", "ip=dhcp", " sss ", "pcr_ids"},
		EncNone:     {"dm_crypt", "clevis", "cryptsetup", "recovery", "ip=dhcp", "agentbox-luks.key", "tpmrm0"},
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
		"systemctl mask apt-daily.timer apt-daily-upgrade.timer", "RuntimeMaxSec=120"}
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
				for _, a := range append(append([]string{"/tmp/ab", "| head -1", "mktemp -d /run/agentbox-firstboot"}, encAvoid[enc]...), bootAvoid[boot]...) {
					if strings.Contains(s, a) {
						t.Errorf("unexpected %q", a)
					}
				}
				if i, j := strings.Index(s, "early-commands:"), strings.Index(s, "need exactly 1"); i < 0 || j < i || strings.Count(s[i:j], "\n    - ") != 1 {
					t.Error("the disk guard must be early-commands[0]")
				}
				// firstboot: the sha256 pin, then minisign, and only then does anything unpack or install
				last := -1
				for _, step := range []string{`h=$(sha256sum "$D/ab.tgz")`, `[ "$h" = "$AGENTBOX_RELEASE_SHA256" ] || {`,
					`minisign -Vm "$D/ab.tgz" -P "$AGENTBOX_MINISIGN_PUBKEY" || {`, `tar -xzf "$D/ab.tgz"`, `"$D/x/install.sh" --from-firstboot`,
					"systemctl start agentbox-reconcile.service", "touch /var/lib/agentbox/.firstboot-done", "'AGENTBOX_RELEASE_SHA256=" + testSHA + "'"} {
					i := strings.Index(s, step)
					if i <= last {
						t.Errorf("firstboot step %q missing or out of order", step)
					}
					last = i
				}
				if regexp.MustCompile(`clevis luks bind .*(^| )-y( |$)`).MatchString(s) {
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
		{"33-char user", "admin user", EncNone, func(c *Config) { c.AdminUser = strings.Repeat("a", 33) }},
		{"serial with space (shell/YAML injection)", "disk serial", EncNone, func(c *Config) { c.DiskSerial = "S4EV 123; rm -rf /" }},
		{"serial with quote", "disk serial", EncNone, func(c *Config) { c.DiskSerial = "S4EV'x" }},
		{"serial with newline", "disk serial", EncNone, func(c *Config) { c.DiskSerial = "S4EV\n" }},
		{"empty serial", "disk serial", EncNone, func(c *Config) { c.DiskSerial = "" }},
		{"quote in ssh comment", "ssh key", EncNone, func(c *Config) { c.SSHKeys = []string{"ssh-ed25519 AAAA you'@laptop"} }},
		{"truncated ed25519 blob", "ssh key", EncNone, func(c *Config) { c.SSHKeys = []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGb9c8 you@laptop"} }},
		{"no ssh keys", "--ssh-key", EncNone, func(c *Config) { c.SSHKeys = nil }},
		{"plain password", "password hash", EncNone, func(c *Config) { c.AdminPasswordHash = "hunter2" }},
		{"impossible hash tail", "password hash", EncNone, func(c *Config) { c.AdminPasswordHash = "$6$saltsalt$" + strings.Repeat("a", 86) }},
		{"http release", "release url", EncNone, func(c *Config) { c.ReleaseURL = "http://releases.example.com/a.tgz" }},
		{"query in release url", "release url", EncNone, func(c *Config) { c.ReleaseURL = "https://x.example.com/a.tgz?x=1&y=$(id)" }},
		{"vm release url without --dev", "release url", EncNone, func(c *Config) { c.ReleaseURL = "http://10.0.2.2:7600/a.tgz" }},
		{"--dev http url off the vm host", "release url", EncNone, func(c *Config) { c.Dev, c.ReleaseURL = true, "http://192.168.1.5:7600/a.tgz" }},
		{"--dev url without port", "release url", EncNone, func(c *Config) { c.Dev, c.ReleaseURL = true, "http://10.0.2.2/a.tgz" }},
		{"--dev url with query", "release url", EncNone, func(c *Config) { c.Dev, c.ReleaseURL = true, "http://10.0.2.2:7600/a.tgz?$(id)" }},
		{"no release sha256", "release sha256", EncNone, func(c *Config) { c.ReleaseSHA256 = "" }},
		{"short release sha256", "release sha256", EncNone, func(c *Config) { c.ReleaseSHA256 = testSHA[:63] }},
		{"release sha256 with shell", "release sha256", EncNone, func(c *Config) { c.ReleaseSHA256 = testSHA[:60] + "$(x)" }},
		{"tang without thp", "tang thp", EncTPM2Tang, func(c *Config) { c.TangThp = "" }},
		{"tang url with quote", "tang url", EncTPM2Tang, func(c *Config) { c.TangURL = "http://x'y" }},
		{"tang hostname", "tang url", EncTPM2Tang, func(c *Config) { c.TangURL = "http://tang.lan:7500" }},
		{"tang https", "tang url", EncTPM2Tang, func(c *Config) { c.TangURL = "https://192.168.1.10" }},
		{"tang public ip", "tang url", EncTPM2Tang, func(c *Config) { c.TangURL = "http://203.0.113.5:7500" }},
		{"tang bad ip", "tang url", EncTPM2Tang, func(c *Config) { c.TangURL = "http://999.1.1.1" }},
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

func TestValidateAccepts(t *testing.T) {
	for _, s := range []string{"QM00001", "QEMU_NVMe_Ctrl_QM00001_1", "WDC_WD10EZEX-08WN4A0_WD-WCC6Y1234567", "Generic_Flash_Disk_FBA5D7A1-0:0"} {
		c := validConfig(t, EncNone, "uefi")
		c.DiskSerial = s
		if err := c.Validate(); err != nil {
			t.Errorf("serial %q: %v", s, err)
		}
	}
	for _, u := range []string{"https://releases.example.com/a.tgz", "http://10.0.2.2:7600/agentbox-0.0.1-gate.tgz"} {
		c := validConfig(t, EncNone, "uefi")
		c.Dev, c.ReleaseURL = true, u
		if err := c.Validate(); err != nil {
			t.Errorf("--dev release url %q: %v", u, err)
		}
	}
	for _, u := range []string{"boxadmin", "ubuntu", "owner"} {
		c := validConfig(t, EncNone, "uefi")
		c.AdminUser = u
		if err := c.Validate(); err != nil {
			t.Errorf("user %q: %v", u, err)
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
	iso := filepath.Join(dir, "seed.iso")
	if err := BuildCidataISO(dir, iso); err != nil {
		t.Fatal(err)
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
			if err := WriteNoCloud(validConfig(t, enc, boot), dir, time.Unix(0, 0)); err != nil {
				t.Fatal(err)
			}
			args := append(append([]string{}, cmd[1:]...), filepath.Join("..", "..", "hack", "verify-seed.py"), filepath.Join(dir, "user-data"))
			if out, err := exec.Command(cmd[0], args...).CombinedOutput(); err != nil {
				t.Errorf("%s/%s: %v\n%s", enc, boot, err, out)
			}
		}
	}
}
