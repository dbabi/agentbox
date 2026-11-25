#!/bin/sh
# Sign and publish a release that CI drafted (.github/workflows/release.yml).
#   hack/sign-release.sh <tag>            MINISIGN_KEY defaults to ~/agentbox-keys/minisign.key
# It checks CI's tarball against SHA256SUMS and its GitHub provenance, and that the ci and release workflows passed on
# the tagged commit. It rebuilds that commit unsigned with the same Go version, and signs CI's tarball only if the two
# builds are byte-identical. It publishes only if the signature verifies with keys/release-minisign.pub from this
# checkout, not from the tagged one. The secret key never leaves this machine.
# The tagged code runs only in the rebuild, through sudo as AGENTBOX_BUILD_USER (default agentbox-build): a user of its
# own, which must not be able to read the key, write a directory on PATH or use your terminal. The rebuild checks all
# three before it builds. CI's tarball is hashed before the rebuild, and the copy that gets signed stays in a temp dir
# that only you can open.
set -eu
TAG=${1:?usage: hack/sign-release.sh <tag>}
REPO=${AGENTBOX_REPO:-dbabi/agentbox}
KEY=${MINISIGN_KEY:-$HOME/agentbox-keys/minisign.key}
BUILD=${AGENTBOX_BUILD_USER:-agentbox-build}
PUB=$(cd "$(dirname "$0")/.." && pwd)/keys/release-minisign.pub
die() { echo "sign-release: $*" >&2; exit 1; }
for c in base64 gh git go minisign od shasum sudo tar; do command -v $c >/dev/null || die "$c not installed"; done
[ -f "$KEY" ] || die "no minisign secret key at $KEY (issue: make it with minisign -G)"
[ -f "$PUB" ] || die "no committed public key at $PUB"
u=$(id -u "$BUILD" 2>/dev/null) || die "no user $BUILD to run the rebuild as (Release-Pipeline.md, \"The build user\")"
[ "$u" != 0 ] && [ "$u" != "$(id -u)" ] || die "$BUILD is root or you; the rebuild needs a user of its own"
# the key ID: bytes 2-9 of the base64 line in a .pub or .minisig file
keyid() { sed -n 2p "$1" | base64 -d 2>/dev/null | od -An -tx1 -j2 -N8 | tr -d ' \n'; }
W=$(mktemp -d "${TMPDIR:-/tmp}/agentbox-sign.XXXX")
trap 'rm -rf "$W"' EXIT

gh release download "$TAG" -R "$REPO" -D "$W/ci" -p 'agentbox-*.tgz' -p SHA256SUMS -p BUILDINFO
commit=$(sed -n 's/^commit //p' "$W/ci/BUILDINFO"); gover=$(sed -n 's/^go //p' "$W/ci/BUILDINFO"); ver=$(sed -n 's/^version //p' "$W/ci/BUILDINFO")
[ -n "$commit" ] && [ -n "$gover" ] && [ -n "$ver" ] || die "BUILDINFO is incomplete"
[ "v$ver" = "$TAG" ] || die "BUILDINFO version $ver does not match tag $TAG"
tgz=agentbox-$ver.tgz
(cd "$W/ci" && shasum -a 256 -c SHA256SUMS) || die "CI tarball does not match SHA256SUMS"
ci=$(shasum -a 256 "$W/ci/$tgz" | cut -d' ' -f1) # before any tagged code runs
gh attestation verify "$W/ci/$tgz" -R "$REPO" --signer-workflow "$REPO/.github/workflows/release.yml" \
  --source-ref "refs/tags/$TAG" --source-digest "$commit" >/dev/null ||
  die "no valid GitHub build provenance for $tgz from release.yml at $TAG ($commit)"
# release.yml runs only go vet and go test; ci also runs lint, govulncheck, the root audit tests and the BIOS gates
for wf in ci release; do
  n=$(gh run list -R "$REPO" --commit "$commit" --workflow "$wf" --event push --status success --json databaseId --jq length)
  [ "${n:-0}" -gt 0 ] || die "no successful $wf workflow run for a push of $commit; not signing"
done

git clone -q --no-checkout "https://github.com/$REPO.git" "$W/src"
git -C "$W/src" checkout -q --detach "$commit"
[ "$(git -C "$W/src" rev-parse "$TAG^{commit}")" = "$commit" ] || die "tag $TAG does not point at $commit"
# The rebuild: sh -c runs this as $BUILD, with only the environment passed below. It refuses to build if $BUILD can
# read the key, can write a directory on its PATH (a fake minisign or gh there would run below, with your key and its
# password), or runs on your terminal (it could read the password as you type it). It gets the clone on stdin and
# writes the tarball to stdout.
rebuild='set -eu
key=$1 ver=$2 gover=$3 sdk=$4 tty=$5 me=$(id -un)
refuse() { echo "sign-release: $me $*; not building" >&2; exit 1; }
# a toolchain in ~/sdk/<goversion> (from dl.google.com) wins; otherwise Go downloads it through its module proxy
if [ -x "$sdk/bin/go" ]; then PATH=$sdk/bin:$PATH GOTOOLCHAIN=local; else GOTOOLCHAIN=$gover; fi
export PATH GOTOOLCHAIN
[ ! -r "$key" ] || refuse "can read $key"
set -f; IFS=:
for d in $PATH; do p=${d:-.}; while [ ! -e "$p" ]; do p=$(dirname "$p"); done; [ ! -w "$p" ] || refuse "can write $p (PATH has ${d:-.})"; done
unset IFS; set +f
case $(ps -o tty= -p $$ | tr -d " ") in "" | "?" | "??") ;; "$tty") refuse "runs on your terminal; sudo needs Defaults use_pty" ;; esac
d=$(mktemp -d /tmp/agentbox-build.XXXXXX)
trap "chmod -R u+w \"$d\"; rm -rf \"$d\"" EXIT
mkdir "$d/src" && tar -C "$d/src" -xf - && cd "$d/src"
HOME=$d go run ./hack/release -unsigned -version "$ver" -out "$d/out" >&2
cat "$d/out/agentbox-$ver.tgz"'
tty=$(ps -o tty= -p $$ | tr -d ' ')
# no macOS ._ files or extended attributes in the stream: git in the rebuild would count them as changes
# shellcheck disable=SC2024 # you write the tarball the rebuild sends, not $BUILD
COPYFILE_DISABLE=1 tar --no-xattrs -C "$W/src" -cf - . |
  sudo -u "$BUILD" env -i PATH="$PATH" ${GOPROXY+"GOPROXY=$GOPROXY"} ${GOSUMDB+"GOSUMDB=$GOSUMDB"} \
    /bin/sh -c "$rebuild" sh "$KEY" "$ver" "$gover" "$HOME/sdk/$gover" "$tty" >"$W/local.tgz" ||
  die "the rebuild as $BUILD failed; not signing"
mine=$(shasum -a 256 "$W/local.tgz" | cut -d' ' -f1)
[ "$ci" = "$mine" ] || die "local rebuild $mine differs from CI's $ci; not signing"

# the same command and trusted comment as hack/release, so the signature matches a local make release
minisign -S -s "$KEY" -m "$W/ci/$tgz" -t "agentbox $ver" || die "minisign could not sign $tgz"
sig=$W/ci/$tgz.minisig
want=$(keyid "$PUB"); got=$(keyid "$sig")
[ -n "$want" ] && [ "$got" = "$want" ] || die "$KEY has key ID ${got:-unknown}, but $PUB has $want; not publishing"
tc=$(minisign -V -Q -p "$PUB" -m "$W/ci/$tgz") || die "signature does not verify with $PUB; not publishing"
[ "$tc" = "agentbox $ver" ] || die "trusted comment is \"$tc\", not \"agentbox $ver\"; not publishing"

gh release upload "$TAG" -R "$REPO" "$sig" --clobber
gh release edit "$TAG" -R "$REPO" --draft=false
echo "published $TAG"
echo "seed flags: --release-url https://github.com/$REPO/releases/download/$TAG/$tgz --release-sha256 $ci"
