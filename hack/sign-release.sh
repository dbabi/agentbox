#!/bin/sh
# Sign and publish a release that CI drafted (.github/workflows/release.yml).
#   hack/sign-release.sh <tag>            MINISIGN_KEY defaults to ~/agentbox-keys/minisign.key
# It checks CI's tarball against SHA256SUMS and its GitHub provenance, rebuilds the same commit with the same Go
# version, and signs only if the two builds are byte-identical. The secret key never leaves this machine.
set -eu
TAG=${1:?usage: hack/sign-release.sh <tag>}
REPO=${AGENTBOX_REPO:-dbabi/agentbox}
KEY=${MINISIGN_KEY:-$HOME/agentbox-keys/minisign.key}
die() { echo "sign-release: $*" >&2; exit 1; }
for c in gh git go minisign shasum; do command -v $c >/dev/null || die "$c not installed"; done
[ -f "$KEY" ] || die "no minisign secret key at $KEY (issue: make it with minisign -G)"
W=$(mktemp -d "${TMPDIR:-/tmp}/agentbox-sign.XXXX")
trap 'rm -r "$W"' EXIT

gh release download "$TAG" -R "$REPO" -D "$W/ci" -p 'agentbox-*.tgz' -p SHA256SUMS -p BUILDINFO
commit=$(sed -n 's/^commit //p' "$W/ci/BUILDINFO"); gover=$(sed -n 's/^go //p' "$W/ci/BUILDINFO"); ver=$(sed -n 's/^version //p' "$W/ci/BUILDINFO")
[ -n "$commit" ] && [ -n "$gover" ] && [ -n "$ver" ] || die "BUILDINFO is incomplete"
[ "v$ver" = "$TAG" ] || die "BUILDINFO version $ver does not match tag $TAG"
tgz=agentbox-$ver.tgz
(cd "$W/ci" && shasum -a 256 -c SHA256SUMS) || die "CI tarball does not match SHA256SUMS"
gh attestation verify "$W/ci/$tgz" -R "$REPO" >/dev/null || die "no valid GitHub build provenance for $tgz"

git clone -q --no-checkout "https://github.com/$REPO.git" "$W/src"
git -C "$W/src" checkout -q --detach "$commit"
[ "$(git -C "$W/src" rev-parse "$TAG^{commit}")" = "$commit" ] || die "tag $TAG does not point at $commit"
# a toolchain in ~/sdk/<goversion> (from dl.google.com) wins; otherwise Go downloads it through its module proxy
if [ -x "$HOME/sdk/$gover/bin/go" ]; then tc="GOTOOLCHAIN=local PATH=$HOME/sdk/$gover/bin:$PATH"; else tc="GOTOOLCHAIN=$gover"; fi
(cd "$W/src" && env $tc go run ./hack/release -version "$ver" -key "$KEY" -out "$W/local")
ci=$(shasum -a 256 "$W/ci/$tgz" | cut -d' ' -f1); mine=$(shasum -a 256 "$W/local/$tgz" | cut -d' ' -f1)
[ "$ci" = "$mine" ] || die "local rebuild $mine differs from CI's $ci; not signing"

minisign -V -p "${KEY%.key}.pub" -m "$W/local/$tgz" >/dev/null 2>&1 || echo "sign-release: note: could not verify with ${KEY%.key}.pub"
gh release upload "$TAG" -R "$REPO" "$W/local/$tgz.minisig" --clobber
gh release edit "$TAG" -R "$REPO" --draft=false
echo "published $TAG"
echo "seed flags: --release-url https://github.com/$REPO/releases/download/$TAG/$tgz --release-sha256 $ci"
