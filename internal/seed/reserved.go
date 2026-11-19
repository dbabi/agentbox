package seed

import (
	"slices"
	"strings"
)

// subiquityReserved is what subiquity 26.04.1 refuses with "Username is reserved by the system": the first token of
// each line of https://github.com/canonical/subiquity/blob/26.04.1/reserved-usernames
// (md5 c04b2d29bb05931d4cd955ac3cb55ce0). Names only; the upstream file's text is not copied.
var subiquityReserved = strings.Fields(`root daemon bin sys sync games man lp mail news uucp proxy www-data backup list
irc gnats nobody adm tty disk kmem dialout fax voice cdrom floppy tape sudo audio dip operator src shadow utmp video
sasl plugdev staff users nogroup netplan ftn mysql tac-plus alias qmail qmaild qmails qmailr qmailq qmaill qmailp
asterisk vpopmail vchkpw slurm hacluster haclient grsec-tpe grsec-sock-all grsec-sock-clt grsec-sock-srv grsec-proc
ceph opensrf libvirt-qemu admin Debian-exim bind crontab cupsys dcc dhcp dictd dnsmasq dovecot fetchmail firebird ftp
fuse gdm haldaemon hplilp identd input jwhois klog kvm lpadmin maas messagebus mythtv netdev powerdev radvd render
saned sbuild scanner sgx slocate ssh sshd ssl-cert sslwrap statd syslog telnetd tftpd`)

// takenUsers already exist in the 26.04.1 server target as a user or a group (subiquity's in-target useradd also makes
// a same-name group, so either fails after the disk is wiped) or are agentbox's own accounts (ARCHITECTURE.md §12).
// shortcut: field 1 of etc/passwd and etc/group in casper/ubuntu-server-minimal.ubuntu-server.squashfs of both pinned
// ISOs (usbmux is amd64 only), minus what subiquityReserved and reservedUser's prefixes refuse; package manifests miss
// group-only names. Re-derive on ISO bumps; hack/gate.sh checks that the seed refuses every account and group of the
// installed box.
var takenUsers = strings.Fields(`clock dhcpcd fwupd-refresh landscape lxd polkitd rdma tcpdump tss usbmux uuidd agentbox ntfy`)

func reservedUser(u string) bool {
	for _, p := range []string{"_", "systemd-", "agentbox-", "ag-", "app-"} {
		if strings.HasPrefix(u, p) {
			return true
		}
	}
	return slices.Contains(subiquityReserved, u) || slices.Contains(takenUsers, u)
}
