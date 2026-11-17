# make release VERSION=<ver> MINISIGN_KEY=<minisign secret key file> [DIST=dist]
# Writes DIST/agentbox-<ver>.tgz and its .minisig and prints the seed's --release-sha256. hack/gate.sh signs its test
# releases with a throwaway key in .vm/keys; never commit a secret key.
DIST ?= dist

release:
	go run ./hack/release -version "$(VERSION)" -key "$(MINISIGN_KEY)" -out "$(DIST)"

.PHONY: release
