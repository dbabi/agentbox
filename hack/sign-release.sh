#!/bin/sh
# Sign and publish a release that CI drafted (.github/workflows/release.yml).
#   hack/sign-release.sh <tag>            MINISIGN_KEY defaults to ~/agentbox-keys/minisign.key
# It checks CI's tarball against SHA256SUMS and its GitHub provenance, and that the ci and release workflows passed on
# the tagged commit. It rebuilds that commit unsigned with the same Go version, and signs CI's tarball only if the two
# builds are byte-identical. It publishes only if the signature verifies with keys/release-minisign.pub from this
# checkout, not from the tagged one. The secret key never leaves this machine, and the tagged code never gets its path.
set -eu
TAG=${1:?usage: hack/sign-release.sh <tag>}
REPO=${AGENTBOX_REPO:-dbabi/agentbox}
KEY=${MINISIGN_KEY:-$HOME/agentbox-keys/minisign.key}
PUB=$(cd "$(dirname "$0")/.." && pwd)/keys/release-minisign.pub
die() { echo "sign-release: $*" >&2; exit 1; }
for c in base64 gh git go minisign od shasum; do command -v $c >/dev/null || die "$c not installed"; done
[ -f "$KEY" ] || die "no minisign secret key at $KEY (issue: make it with minisign -G)"
[ -f "$PUB" ] || die "no committed public key at $PUB"
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
# a toolchain in ~/sdk/<goversion> (from dl.google.com) wins; otherwise Go downloads it through its module proxy
# exported, not passed as "env $tc": a PATH entry with a space would split into separate words
if [ -x "$HOME/sdk/$gover/bin/go" ]; then export GOTOOLCHAIN=local PATH="$HOME/sdk/$gover/bin:$PATH"; else export GOTOOLCHAIN="$gover"; fi
# the tagged code builds unsigned, without the key path in its arguments or environment
(unset MINISIGN_KEY; cd "$W/src" && go run ./hack/release -unsigned -version "$ver" -out "$W/local")
ci=$(shasum -a 256 "$W/ci/$tgz" | cut -d' ' -f1); mine=$(shasum -a 256 "$W/local/$tgz" | cut -d' ' -f1)
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
