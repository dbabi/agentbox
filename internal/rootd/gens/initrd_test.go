package gens

import (
	"slices"
	"strings"
	"testing"
)

// lsinitrd lines from the tpm2 VM's initrd.img-7.0.0-43-generic (dracut 110), with the sss and tpm2 pins a tpm2+tang
// initrd has (usr/bin, as in the tpm2+tang VM's)
const initrdList = `-rwxr-xr-x   1 root     root        22744 Mar  8  2024 usr/bin/clevis-decrypt-sss
-rwxr-xr-x   1 root     root         3888 Mar  8  2024 usr/bin/clevis-decrypt-tang
-rwxr-xr-x   1 root     root         3345 Mar  8  2024 usr/bin/clevis-decrypt-tpm2
-rwxr-xr-x   1 root     root       134536 Sep 16 14:55 usr/bin/systemd-cryptsetup
-rwxr-xr-x   1 root     root         2466 Mar 16  2026 usr/libexec/clevis-luks-askpass
-rw-r--r--   1 root     root       106633 Oct 23 11:56 usr/lib/modules/7.0.0-43-generic/kernel/drivers/nvme/host/nvme-core.ko.zst
-rw-r--r--   1 root     root        51209 Oct 23 11:56 usr/lib/modules/7.0.0-43-generic/kernel/drivers/nvme/host/nvme.ko.zst
-rw-r--r--   1 root     root      1311090 Oct 23 11:56 usr/lib/modules/7.0.0-43-generic/kernel/fs/btrfs/btrfs.ko.zst
-rw-r--r--   1 root     root         6119 Oct 23 11:56 usr/lib/modules/7.0.0-43-generic/kernel/drivers/watchdog/i6300esb.ko.zst
`

const crypttab = "croot /dev/disk/by-uuid/40c5699d-54cf-46bb-a07e-4adf9e3629c7 none luks,x-initrd.attach,timeout=300s\n"

func TestInitrdProblems(t *testing.T) {
	tang := Mode{Encrypted: true, Tang: true, Drivers: []string{"nvme.ko", "nvme-core.ko", "i6300esb.ko"}}
	if miss := InitrdProblems(initrdList, crypttab, tang); len(miss) != 0 {
		t.Fatalf("a good initrd: %v", miss)
	}
	without := func(ss ...string) string {
		var keep []string
		for _, l := range strings.Split(initrdList, "\n") {
			if !slices.ContainsFunc(ss, func(s string) bool { return strings.Contains(l, s) }) {
				keep = append(keep, l)
			}
		}
		return strings.Join(keep, "\n")
	}
	tpm2 := Mode{Encrypted: true, Drivers: tang.Drivers}
	// what lsinitrd also lists by these names: dracut's module names, the units, the generator, links (#215)
	others := "dracut modules:\nsystemd-cryptsetup\nclevis\nclevis-pin-sss\nclevis-pin-tang\nclevis-pin-tpm2\n" +
		"-rwxr-xr-x   1 root     root        59872 Sep 16 14:55 usr/lib/systemd/system-generators/systemd-cryptsetup-generator\n" +
		"-rw-r--r--   1 root     root          303 Mar 16  2026 usr/lib/systemd/system/clevis-luks-askpass.path\n" +
		"-rw-r--r--   1 root     root          229 Mar 16  2026 usr/lib/systemd/system/clevis-luks-askpass.service\n" +
		"lrwxrwxrwx   1 root     root           28 Sep 16 14:55 usr/lib/systemd/systemd-cryptsetup -> ../../bin/systemd-cryptsetup\n" +
		"lrwxrwxrwx   1 root     root           48 Nov 19 02:34 etc/systemd/system/cryptsetup.target.wants/clevis-luks-askpass.path -> /usr/lib/systemd/system/clevis-luks-askpass.path\n"
	for _, tc := range []struct {
		name, list, crypttab string
		m                    Mode
		want                 []string
	}{
		{"clevis removed", without("clevis"), crypttab, tang, []string{"no clevis-luks-askpass", "no clevis-decrypt-tpm2", "no clevis-decrypt-sss", "no clevis-decrypt-tang"}},
		{"crypttab dropped (dracut could not see the disk)", initrdList, "", tang, []string{"etc/crypttab has no croot line"}},
		{"no systemd-cryptsetup", without("systemd-cryptsetup"), crypttab, tpm2, []string{"no systemd-cryptsetup"}},
		{"tpm2 pin missing, tpm2 mode", without("clevis-decrypt-tpm2"), crypttab, tpm2, []string{"no clevis-decrypt-tpm2"}},
		{"tpm2 pin missing, tpm2+tang mode", without("clevis-decrypt-tpm2"), crypttab, tang, []string{"no clevis-decrypt-tpm2"}},
		{"sss pin missing, tpm2+tang mode", without("clevis-decrypt-sss"), crypttab, tang, []string{"no clevis-decrypt-sss"}},
		{"only units, a generator, links and module names", without("usr/bin/", "usr/libexec/") + others, crypttab, tang,
			[]string{"no clevis-luks-askpass", "no systemd-cryptsetup", "no clevis-decrypt-tpm2", "no clevis-decrypt-sss", "no clevis-decrypt-tang"}},
		{"recorded storage driver missing", without("/nvme.ko"), crypttab, tang, []string{"no nvme.ko"}},
		{"recorded watchdog driver missing (no unattended fallback 4)", without("i6300esb"), crypttab, tang, []string{"no i6300esb.ko"}},
		{"none mode needs btrfs only", without("clevis"), "", Mode{}, nil},
		{"none mode without btrfs", without("btrfs"), "", Mode{}, []string{"no btrfs.ko"}},
		{"tpm2 mode needs neither sss nor tang", without("clevis-decrypt-sss", "clevis-decrypt-tang"), crypttab, tpm2, nil},
	} {
		if got := InitrdProblems(tc.list, tc.crypttab, tc.m); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestRecordedDrivers(t *testing.T) {
	conf := "hostonly_cmdline=\"no\"\nadd_drivers+=\" nvme nvme_core virtio_blk \"\nforce_drivers+=\" i6300esb \"\n# add_drivers+=\" ignored \"\n"
	dep := "kernel/drivers/nvme/host/nvme-core.ko.zst: kernel/drivers/nvme/common/nvme-auth.ko.zst\n" +
		"kernel/drivers/nvme/host/nvme.ko.zst: kernel/drivers/nvme/host/nvme-core.ko.zst\n" +
		"kernel/drivers/watchdog/i6300esb.ko.zst:\n" +
		"kernel/fs/btrfs/btrfs.ko.zst: kernel/lib/raid6/raid6_pq.ko.zst\n"
	builtin := "kernel/drivers/block/virtio_blk.ko\nkernel/drivers/scsi/sd_mod.ko\n" // 7.0.0-30's own format
	// virtio_blk is built into this kernel: no module file, nothing to look for
	if got := RecordedDrivers(conf, dep, builtin); !slices.Equal(got, []string{"nvme.ko", "nvme-core.ko", "i6300esb.ko"}) {
		t.Fatalf("RecordedDrivers = %v", got)
	}
	if got := RecordedDrivers("hostonly_cmdline=\"no\"\n", dep, builtin); got != nil {
		t.Fatalf("no drivers recorded: %v", got)
	}
	// a kernel that ships neither the recorded disk driver nor the watchdog driver: the gate must still look for both
	if got := RecordedDrivers(`add_drivers+=" nvme ahci "`+"\n"+`force_drivers+=" softdog "`, dep, builtin); !slices.Equal(got, []string{"nvme.ko", "ahci.ko", "softdog.ko"}) {
		t.Fatalf("drivers missing from the kernel: %v", got)
	}
	if miss := InitrdProblems(initrdList, "", Mode{Drivers: RecordedDrivers(`add_drivers+=" ahci "`, dep, builtin)}); !slices.Equal(miss, []string{"no ahci.ko"}) {
		t.Fatalf("a recorded driver the kernel lacks passed the gate: %v", miss)
	}
}
