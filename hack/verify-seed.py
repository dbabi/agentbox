#!/usr/bin/env python3
"""Verify a rendered seed: real YAML parse, autoinstall shape, and `sh -n` on every embedded script.

usage: uv run --with pyyaml python3 -I hack/verify-seed.py <seed-dir>/user-data
"""
import re
import subprocess
import sys
import tempfile

import yaml


def sh_n(name, script):
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
        f.write(script)
    r = subprocess.run(["dash", "-n", f.name], capture_output=True, text=True)  # the installer runs dash; macOS sh is bash
    if r.returncode:
        sys.exit(f"FAIL sh -n {name}: {r.stderr.strip()}")
    print(f"ok   sh -n {name}")


def heredoc(script, tag):
    m = re.search(rf"<<'{tag}'\n(.*?)\n{tag}\n", script, re.S)
    if not m:
        sys.exit(f"FAIL heredoc {tag} not found")
    return m.group(1)


def main(path):
    text = open(path).read()
    if not text.startswith("#cloud-config\n"):
        sys.exit("FAIL first line must be #cloud-config")
    doc = yaml.safe_load(text)
    ai = doc["autoinstall"]
    assert ai["version"] == 1
    assert ai["ssh"]["allow-pw"] is False and ai["ssh"]["authorized-keys"], "ssh"
    cfg = ai["storage"]["config"]
    disk = next(x for x in cfg if x["type"] == "disk")
    assert disk.get("serial"), "disk must be matched by serial"
    assert "need exactly 1" in ai["early-commands"][0], "early-commands[0] must be the disk guard"
    assert ai["apt"]["fallback"] == "abort" and ai["kernel-crash-dumps"] == {"enabled": False}
    assert ai["identity"]["username"] not in ("admin", "root", "agentbox"), "reserved username"
    for dev in {x["device"] for x in cfg if x["type"] == "partition"}:  # subiquity NotFinalPartitionError
        sizes = [x["size"] for x in cfg if x["type"] == "partition" and x["device"] == dev]
        assert sizes[-1] == -1 and -1 not in sizes[:-1], "size -1 must be the last partition"
    assert ai["storage"]["swap"] == {"size": 0}
    ids = {x["id"] for x in cfg}
    for x in cfg:  # every reference points at a declared id
        for ref in ("device", "volume"):
            if ref in x:
                assert x[ref] in ids, f"{x['id']}.{ref} -> {x[ref]} undefined"
    print(f"ok   yaml: {len(cfg)} storage actions, references resolve")
    for i, c in enumerate(ai.get("early-commands", [])):
        sh_n(f"early-commands[{i}]", c)
    late = ai["late-commands"]
    assert len(late) == 1
    script = late[0]
    sh_n("late-commands", script)
    assert 'mount --make-rslave "/mnt/new/$d"' in script, "rbind copies must be slaves before umount -R"
    sh_n("09_agentbox", heredoc(script, "G9"))
    sh_n("agentbox-firstboot", heredoc(script, "FB"))
    sh_n("agentbox-boot-deadline", heredoc(script, "BD"))
    for bad in ("PRIVATE KEY", "|| true", "-y -k"):
        assert bad not in text, f"forbidden text {bad!r}"
    print("ok   no private keys, no failure suppression")


if __name__ == "__main__":
    main(sys.argv[1])
