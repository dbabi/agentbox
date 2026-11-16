# agentbox threat model (one page)

Source of truth: `~/workplace/ai-os-research/ARCHITECTURE.md` v5.1, §10. Update both together.

## What we protect
1. **The host:** the OS generations, the boot chain, and other users.
2. **Secrets:** LLM API keys, the GitHub token, Tailscale and ntfy credentials, the LUKS key.
3. **The owner's data and LAN:** files in `/srv` and workspaces, plus devices on the home network.
4. **Integrity of approvals, audit, and memory.**

## Who attacks, and through what
| Attacker | Entry point |
|---|---|
| Prompt injection (most likely) | Web pages, package READMEs, issues and PRs, logs, other agents' messages, memory |
| A compromised agent CLI or dependency | Code running inside a task container |
| Thief | The disk alone, or the whole powered-off machine |
| Someone on the LAN or tailnet | Exposed ports, the approval page |
| A bug in our own services | Parsers in agentboxd, proxy, keys, git, approvald and auditd |

## Trust boundaries
- internet ↔ proxy
- container ↔ host kernel
- task ↔ its own sockets
- agentboxd ↔ rootd
- agent ↔ agent
- model ↔ policy
- memory ↔ prompts
- phone ↔ approvald
- disk ↔ thief
- OS generation ↔ persistent state

## Non-negotiables (tests must prove each)
1. Tasks have **no network** (`Network=none`). Egress goes only through the task's own Unix sockets.
2. **No credential exists inside a task.** Keys live in `agentbox-keys`, and the GitHub token lives in `agentbox-git`.
3. **Agents never mutate the running OS.** Changes are built offline into a new generation and committed only after a health check.
4. **rootd executes only the stored operation a human signed**, bound to its immutable inputs and re-checked at execution.
5. **Taint is sticky.** Only a human clears it, after reviewing the diff, with control files called out first.
6. **Nothing persists between tasks** except the sticky-tainted workspace.
7. **The seed and logs contain no plaintext secrets.** The seed holds the admin password hash (sha512-crypt): keep it private. The LUKS key exists only in installer tmpfs and in `recovery.bin`, encrypted to the owner's offline RSA key.

## Accepted residuals (v1)
| Residual | Upgrade path |
|---|---|
| Shared-kernel exploits | v2: microVM tasks |
| Whole-machine theft in `tpm2` mode | Use `tpm2+tang`; v2: UKI with a signed PCR 11 policy |
| An attacker who stays on your LAN with physical access (`tpm2+tang`) | |
| Boot-chain package updates aren't A/B | |
| CDN fronting, and write-capable hosts you allowlist | |
| Root tampering with on-box audit | Ship audit off-box |
| Misleading phone page for *reversible* ops | |
| Jev egress when enabled | |
| Approximate metering for subscription sessions | |
