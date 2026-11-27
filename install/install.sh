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
RCD=/usr/sbin/policy-rc.d
R=$A/releases
N=$R/.$VER.new
mkdir -p "$R"
rm -rf "$N"
mkdir -p "$N/bin" "$N/systemd" "$N/sysusers.d" "$N/tmpfiles.d" "$N/gen" "$N/seccomp" "$N/image"
install -m 0755 "$BIN" "$N/bin/agentbox"
# rootd checks the task image against the release's SHA256SUMS before every load (#102)
install -m 0644 "$S/image/linux-$ARCH/task.oci.tar" "$N/image/task.oci.tar"
install -m 0644 "$S/SHA256SUMS" "$N/SHA256SUMS"
install -m 0644 "$S"/systemd/* "$N/systemd/"
install -m 0644 "$S"/sysusers.d/* "$N/sysusers.d/"
install -m 0644 "$S"/tmpfiles.d/* "$N/tmpfiles.d/"
install -m 0644 "$S"/gen/* "$N/gen/" # rootd refuses to start unless these match its op registry
install -m 0644 "$S"/seccomp/* "$N/seccomp/"
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
# The brokers' credentials (#108): rootd encrypts each secret.set value with systemd-creds, using this host key in
# none mode (the TPM2 in the tpm2 modes); setup makes the key once and leaves an existing one as it is.
systemd-creds setup >/dev/null || die "systemd-creds setup failed"
# The task seccomp profile (§4.2): every task launch names this path.
install -d -m 0711 "$A/control"
install -m 0644 "$R/$VER/seccomp/seccomp-task.json" "$A/control/.seccomp-task.json.new"
mv -f "$A/control/.seccomp-task.json.new" "$A/control/seccomp-task.json"
# Packaged ntfy (§2): agentbox-reconcile then writes its config, tmpfiles, ACLs and firewall drop-in, and enables it.
# Rootless podman runs the tasks (§4.2); uidmap brings newuidmap, dbus-user-session the user bus rootd launches over.
# policy-rc.d keeps the postinst from starting ntfy on its default config (HTTP on :80, every interface).
need=
for p in ntfy podman uidmap dbus-user-session; do
  dpkg -s "$p" 2>/dev/null | grep -qx 'Status: install ok installed' || need="$need $p"
done
# This exact file is install.sh's own: a run that a power cut or SIGKILL stopped before its trap left it (#218).
rcd() { printf '#!/bin/sh\n# agentbox install.sh: no service starts during its apt step\nexit 101\n'; }
if rcd | cmp -s - "$RCD"; then rm -f "$RCD"; fi
if [ -n "$need" ]; then
  [ ! -e "$RCD" ] || die "$RCD exists; remove it and rerun"
  rcd > "$RCD" && chmod 0755 "$RCD"
  trap 'rm -f "$RCD"' EXIT
  trap 'exit 1' HUP INT TERM # dash runs no EXIT trap for a signal that kills it, such as systemd's TERM at a stop
  apt() { DEBIAN_FRONTEND=noninteractive apt-get -q -y -o DPkg::Lock::Timeout=300 --no-install-recommends "$@"; }
  # after an apt step cut off mid-dpkg, apt-get refuses until dpkg configures what it unpacked
  DEBIAN_FRONTEND=noninteractive dpkg --configure -a || die "dpkg --configure -a failed"
  # shellcheck disable=SC2086 # one package name per word
  apt install $need || { apt update && apt install $need; } || die "apt-get install$need failed"
  rm -f "$RCD"; trap - EXIT HUP INT TERM
fi
getent passwd _ntfy >/dev/null || die "the ntfy package made no _ntfy user"
# The ruleset names those users; it must pass nft -c before any unit is enabled (§2).
"$R/$VER/bin/agentbox" fw load -c || die "the firewall ruleset does not pass nft -c"
# No podman auto-update for any user (#109): an image label must never restart a unit. Agent and app uids have no
# login to start it, and the admin has no use for it on this box.
mkdir -p "$ETC/systemd/user"
ln -sfn /dev/null "$ETC/systemd/user/podman-auto-update.timer"
ln -sfn /dev/null "$ETC/systemd/user/podman-auto-update.service"
# PID 1 loads units before /var/lib/agentbox is mounted, so the units are copies on the root file system.
install -m 0644 "$R/$VER"/systemd/* "$ETC/systemd/system/"
systemctl daemon-reload
# Enables every shipped unit that has an [Install] section; agentbox-firstboot itself starts agentbox-reconcile.service.
# shellcheck disable=SC2046 # split on purpose: one unit name per word, and unit names have no spaces
systemctl enable $(grep -l '^\[Install\]' "$R/$VER"/systemd/* | sed 's|.*/||')
sync # firstboot marks itself done next; a power cut must not leave it done with 0-byte unit copies
