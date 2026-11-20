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
L=/usr/lib
R=$A/releases
N=$R/.$VER.new
mkdir -p "$R"
rm -rf "$N"
mkdir -p "$N/bin" "$N/systemd"
install -m 0755 "$BIN" "$N/bin/agentbox"
install -m 0644 "$S"/systemd/* "$N/systemd/"
install -m 0644 "$S/sysusers.conf" "$S/tmpfiles.conf" "$N/"
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
# Users and dirs before any unit that names them (socket units resolve SocketUser= when they start). Copies on the root
# file system, like the units: systemd-sysusers and systemd-tmpfiles read them at every boot.
install -m 0644 "$R/$VER/sysusers.conf" "$L/sysusers.d/agentbox.conf"
systemd-sysusers "$L/sysusers.d/agentbox.conf"
install -m 0644 "$R/$VER/tmpfiles.conf" "$L/tmpfiles.d/agentbox.conf"
systemd-tmpfiles --create "$L/tmpfiles.d/agentbox.conf"
# PID 1 loads units before /var/lib/agentbox is mounted, so the units are copies on the root file system.
install -m 0644 "$R/$VER"/systemd/* /etc/systemd/system/
systemctl daemon-reload
# Enables every shipped unit that has an [Install] section; agentbox-firstboot itself starts agentbox-reconcile.service.
systemctl enable $(grep -l '^\[Install\]' "$R/$VER"/systemd/* | sed 's|.*/||')
sync # firstboot marks itself done next; a power cut must not leave it done with 0-byte unit copies
