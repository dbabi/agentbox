#!/bin/sh
# agentbox release installer (ARCHITECTURE.md §3.1 firstboot step 3, §3.2 Binaries). agentbox-firstboot runs it from
# the extracted tarball after the sha256 pin and minisign checks. v5.2 has no release-update op, so --from-firstboot
# is the only mode. Safe to re-run: a release dir appears only complete (staged, synced, then renamed), and links
# switch by rename.
set -eu
die() { echo "install.sh: $*" >&2; exit 1; }
[ $# -eq 1 ] && [ "$1" = --from-firstboot ] || die "usage: install.sh --from-firstboot (agentbox-firstboot runs it; there is no release-update op)"
[ "$(id -u)" -eq 0 ] || die "run as root"
umask 022 # firstboot runs with umask 077, but agentbox services run as their own uids and exec current/bin/agentbox
S=$(cd "$(dirname "$0")" && pwd)
ARCH=$(dpkg --print-architecture)
BIN="$S/bin/linux-$ARCH/agentbox"
[ -f "$BIN" ] || die "the release has no linux-$ARCH binary"
VER=$("$BIN" version) || die "$BIN does not run on this box"
case $VER in ''|[!0-9A-Za-z]*|*[!0-9A-Za-z._~-]*) die "bad release version '$VER'" ;; esac
A=/var/lib/agentbox
ETC=/etc
L=/usr/lib
R=$A/releases
N=$R/.$VER.new
mkdir -p "$R"
rm -rf "$N"
mkdir -p "$N/bin" "$N/systemd" "$N/sysusers.d" "$N/tmpfiles.d"
install -m 0755 "$BIN" "$N/bin/agentbox"
install -m 0644 "$S"/systemd/* "$N/systemd/"
install -m 0644 "$S"/sysusers.d/* "$N/sysusers.d/"
install -m 0644 "$S"/tmpfiles.d/* "$N/tmpfiles.d/"
if [ -d "$R/$VER" ]; then
  diff -r "$N" "$R/$VER" >/dev/null || { rm -rf "$N"; die "release $VER is already installed with different content"; }
  rm -rf "$N"
else
  sync # btrfs can commit the rename before the staged data: a cut would leave a short release that every rerun refuses
  mv "$N" "$R/$VER"
fi
# Relative targets, so the links also resolve where rescue media mounts @var_lib_agentbox.
cur=$(readlink "$A/current" || :)
if [ "$cur" != "releases/$VER" ]; then
  [ -z "$cur" ] || { ln -sfn "$cur" "$A/.previous.new" && mv -T "$A/.previous.new" "$A/previous"; }
  ln -sfn "releases/$VER" "$A/.current.new" && mv -T "$A/.current.new" "$A/current"
fi
# Users and dirs before any unit that names them: the firewall names every service user and ntfy's packaged _ntfy
# (ARCHITECTURE.md Appendix B), and socket units resolve SocketUser= when they start (§2.1). Copies on the root file
# system, like the units: systemd-sysusers and systemd-tmpfiles read them at every boot.
install -m 0644 "$R/$VER/sysusers.d/agentbox.conf" "$L/sysusers.d/agentbox.conf"
systemd-sysusers "$L/sysusers.d/agentbox.conf"
install -m 0644 "$R/$VER/tmpfiles.d/agentbox.conf" "$L/tmpfiles.d/agentbox.conf"
systemd-tmpfiles --create "$L/tmpfiles.d/agentbox.conf"
# Packaged ntfy (§2): agentbox-reconcile then writes its config, tmpfiles, ACLs and firewall drop-in, and enables it.
# policy-rc.d keeps the postinst from starting ntfy on its default config (HTTP on :80, every interface).
if ! dpkg -s ntfy 2>/dev/null | grep -qx 'Status: install ok installed'; then
  [ ! -e /usr/sbin/policy-rc.d ] || die "/usr/sbin/policy-rc.d exists; remove it and rerun"
  printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod 0755 /usr/sbin/policy-rc.d
  trap 'rm -f /usr/sbin/policy-rc.d' EXIT
  apt() { DEBIAN_FRONTEND=noninteractive apt-get -q -y -o DPkg::Lock::Timeout=300 --no-install-recommends "$@"; }
  apt install ntfy || { apt update && apt install ntfy; } || die "apt-get install ntfy failed"
  rm -f /usr/sbin/policy-rc.d; trap - EXIT
fi
getent passwd _ntfy >/dev/null || die "the ntfy package made no _ntfy user"
# The ruleset names those users; it must pass nft -c before any unit is enabled (§2).
"$R/$VER/bin/agentbox" fw load -c || die "the firewall ruleset does not pass nft -c"
# PID 1 loads units before /var/lib/agentbox is mounted, so the units are copies on the root file system.
install -m 0644 "$R/$VER"/systemd/* "$ETC/systemd/system/"
systemctl daemon-reload
# Enables every shipped unit that has an [Install] section; agentbox-firstboot itself starts agentbox-reconcile.service.
# shellcheck disable=SC2046 # split on purpose: one unit name per word, and unit names have no spaces
systemctl enable $(grep -l '^\[Install\]' "$R/$VER"/systemd/* | sed 's|.*/||')
sync # firstboot marks itself done next; a power cut must not leave it done with 0-byte unit copies
