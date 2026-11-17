#!/bin/sh
# Zero-touch install medium (PLAN.md week 2): the pinned stock 26.04.1 server ISO with `autoinstall ds=nocloud` on its
# GRUB linux lines, so subiquity installs from a cidata seed (`agentbox seed --iso`) without waiting for a typed "yes".
#   hack/remaster-iso.sh <stock.iso> <out.iso> [extra kernel args]
# Only /boot/grub/grub.cfg and its /md5sum.txt line change. The boot setup (El Torito, MBR/GPT, the EFI partition with
# the signed shim and GRUB) is replayed from the stock ISO, so the medium boots the same path, Secure Boot included:
# GRUB does not verify grub.cfg. Extra args go at the end of the line, e.g. console=ttyS0 for a serial console (curtin
# copies console= into the installed system); a USB stick for real hardware needs none.
set -eu
die() { echo "remaster-iso.sh: $*" >&2; exit 1; }
[ $# -eq 2 ] || [ $# -eq 3 ] || die "usage: hack/remaster-iso.sh <stock.iso> <out.iso> [extra kernel args]"
IN=$1 OUT=$2 EXTRA=${3:+ $3}
case $EXTRA in *[!A-Za-z0-9=,.:_\ -]*) die "extra kernel args may use only [A-Za-z0-9=,.:_ -]" ;; esac
command -v xorriso >/dev/null || die "xorriso not installed (brew install xorriso)"
PINS="$(cd "$(dirname "$0")" && pwd)/SHA256SUMS"
want=$(awk -v f="${IN##*/}" '$2 == f {print $1}' "$PINS")
[ -n "$want" ] || die "no pin for ${IN##*/} in $PINS"
[ "$(sha256sum < "$IN" | cut -d' ' -f1)" = "$want" ] || die "$IN does not match its pin in $PINS"
T=$(mktemp -d "${TMPDIR:-/tmp}/remaster.XXXXXX")
trap 'rm -rf "$T"' EXIT
xorriso -osirrox on -indev "$IN" -extract /boot/grub/grub.cfg "$T/stock.cfg" -extract /md5sum.txt "$T/md5sum.txt" >/dev/null 2>&1 ||
  die "could not read /boot/grub/grub.cfg and /md5sum.txt from $IN"
# Before ` ---`: the installer reads them there, and curtin copies only console= and the args after ` ---` into the
# installed system.
L='^[[:space:]]*linux[[:space:]].*/casper/'
sed "\\|$L.* ---| { s| ---| autoinstall ds=nocloud ---|; s|[[:space:]]*\$|$EXTRA|; }" "$T/stock.cfg" > "$T/grub.cfg"
n=$(grep -c "$L" "$T/stock.cfg" || :)
[ "$n" -ge 1 ] && [ "$(grep -c "$L.* autoinstall ds=nocloud ---" "$T/grub.cfg")" -eq "$n" ] ||
  die "not every casper linux line in grub.cfg has ' ---'; the stock ISO changed"
# casper-md5check verifies every file against /md5sum.txt
grep -q ' \./boot/grub/grub\.cfg$' "$T/md5sum.txt" || die "/md5sum.txt has no ./boot/grub/grub.cfg line"
md5=$(openssl dgst -md5 -r "$T/grub.cfg" | cut -d' ' -f1)
awk -v h="$md5" '$2 == "./boot/grub/grub.cfg" { sub(/^[0-9a-f]+/, h) } { print }' "$T/md5sum.txt" > "$T/md5sum.new"
rm -f "$OUT.part" # xorriso would append a session to an existing image
xorriso -indev "$IN" -outdev "$OUT.part" -map "$T/grub.cfg" /boot/grub/grub.cfg -map "$T/md5sum.new" /md5sum.txt \
  -boot_image any replay >"$T/xorriso.log" 2>&1 || { cat "$T/xorriso.log" >&2; die "xorriso failed"; }
xorriso -osirrox on -indev "$OUT.part" -extract /boot/grub/grub.cfg "$T/check.cfg" >/dev/null 2>&1
cmp -s "$T/grub.cfg" "$T/check.cfg" || die "$OUT.part does not carry the new grub.cfg"
# The image layout may move, so the boot images' LBAs (last column) are left out.
boot() { xorriso -indev "$1" -report_el_torito plain -report_system_area plain 2>/dev/null |
  awk '/^System area summary:/; /^El Torito boot img /{ $NF = ""; print }'; }
[ "$(boot "$IN")" = "$(boot "$OUT.part")" ] || die "$OUT.part lost part of the stock boot setup"
mv "$OUT.part" "$OUT"
grep "$L" "$T/grub.cfg"
