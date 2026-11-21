package seed

import (
	"bytes"
	"testing"
)

// FuzzValidate is the trust boundary of `agentbox seed` (issue #10): every operator value lands in YAML and in a root
// shell script, so whatever Validate accepts must render.
func FuzzValidate(f *testing.F) {
	pub, err := testPub()
	if err != nil {
		f.Fatal(err)
	}
	c := validConfig(f, EncTPM2Tang, "uefi")
	f.Add(c.Hostname, c.AdminUser, c.AdminPasswordHash, c.SSHKeys[0], c.DiskSerial, c.Boot, c.Encryption, c.TangURL, c.TangThp,
		c.MinisignPubKey, c.ReleaseURL, c.ReleaseSHA256, false, pub)
	f.Add("agentbox", "root", "$6$rounds=100000$salt$"+string(bytes.Repeat([]byte("a"), 86)), "ssh-rsa AAAAB3NzaC1yc2E=", "x'y", "bios", EncNone, "", "",
		"RW", "http://10.0.2.2:8080/a.tgz", "", true, []byte{})
	f.Add("box", "boxadmin", c.AdminPasswordHash, c.SSHKeys[0], "s", "uefi", EncTPM2Tang, "http://10.0.0.1:0/x", "t", c.MinisignPubKey,
		"https://h:99999/x", c.ReleaseSHA256, false, []byte("-----BEGIN PUBLIC KEY-----\nMAA=\n-----END PUBLIC KEY-----\n"))
	f.Fuzz(func(t *testing.T, host, user, hash, key, serial, boot, enc, tang, thp, mini, rel, sum string, dev bool, pub []byte) {
		c := &Config{Hostname: host, AdminUser: user, AdminPasswordHash: hash, SSHKeys: []string{key}, DiskSerial: serial, Boot: boot,
			Encryption: enc, TangURL: tang, TangThp: thp, RecoveryPubPEM: pub, MinisignPubKey: mini, ReleaseURL: rel, ReleaseSHA256: sum, Dev: dev}
		if c.Validate() != nil {
			return
		}
		if _, err := Render(c); err != nil {
			t.Fatalf("Validate passed, Render failed: %v", err)
		}
	})
}
