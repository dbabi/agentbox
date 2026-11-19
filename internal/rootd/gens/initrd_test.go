package gens

import (
	"slices"
	"strings"
	"testing"
)

// lsinitrd lines from the tpm2 VM's initrd.img-7.0.0-43-generic (dracut 110)
const initrdList = `-rwxr-xr-x   1 root     root         3888 Mar  8  2024 usr/bin/clevis-decrypt-tang
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
	without := func(s string) string {
		var keep []string
		for _, l := range strings.Split(initrdList, "\n") {
			if !strings.Contains(l, s) {
				keep = append(keep, l)
			}
		}
		return strings.Join(keep, "\n")
	}
	for _, tc := range []struct {
		name, list, crypttab string
		m                    Mode
		want                 []string
	}{
		{"clevis removed", without("clevis"), crypttab, tang, []string{"no clevis-luks-askpass", "no clevis-decrypt-tang"}},
		{"crypttab dropped (dracut could not see the disk)", initrdList, "", tang, []string{"etc/crypttab has no croot line"}},
		{"no systemd-cryptsetup", without("systemd-cryptsetup"), crypttab, Mode{Encrypted: true}, []string{"no systemd-cryptsetup"}},
		{"recorded storage driver missing", without("/nvme.ko"), crypttab, tang, []string{"no nvme.ko"}},
		{"recorded watchdog driver missing (no unattended fallback 4)", without("i6300esb"), crypttab, tang, []string{"no i6300esb.ko"}},
		{"none mode needs btrfs only", without("clevis"), "", Mode{}, nil},
		{"none mode without btrfs", without("btrfs"), "", Mode{}, []string{"no btrfs.ko"}},
		{"tpm2 mode needs no tang", without("clevis-decrypt-tang"), crypttab, Mode{Encrypted: true}, nil},
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
