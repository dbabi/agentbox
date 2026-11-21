<!-- Code generated from internal/ops/registry.go by go generate; DO NOT EDIT. -->
# Op registry

Every op, from `internal/ops/registry.go` (ARCHITECTURE.md §5.1, §5.3). Args and outputs show their audit class when it is not `keep` (§9).

| Op | Class | Cedar group | Resource | Args | Outputs | Signature | Bound inputs | Rollback coverage | Reversible | Taints output | Workspace-bindable | Reaches rootd | Batch and quote |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `agent.add` | admin | n/a |  | name |  | none | n/a | n/a |  |  |  | yes |  |
| `agent.attach` | admin | n/a |  | name, workspace |  | none | n/a | n/a |  |  |  | yes |  |
| `agent.remove` | admin | n/a |  | name |  | none | n/a | n/a |  |  |  | yes |  |
| `agent.skills.set` | admin | n/a |  | agent, skills |  | none | n/a | n/a |  |  |  | yes |  |
| `app.deploy` | live | SideEffect | App from `app` | app, context |  | if the manifest or exposure changes, or tainted | CAS digest; base digest; manifest hash | previous image |  |  |  | yes | quotable; CAS binder |
| `app.logs` | read | Read | App from `app` | app, lines? | log (hash) | none | n/a | n/a |  | yes |  | yes |  |
| `app.remove` | live | SideEffect | App from `app` | app |  | always | app ID | previous image |  |  |  | yes | quotable; always exact |
| `app.restart` | Safe | Safe | App from `app` | app |  | none | app ID | none |  |  |  | yes | quotable; always exact |
| `app.rollback` | live | SideEffect | App from `app` | app, imageDigest |  | always | app ID; image digest | previous image |  |  |  | yes | quotable; always exact |
| `app.start` | Safe | Safe | App from `app` | app |  | none | app ID | none |  |  |  | yes | quotable; always exact |
| `app.status` | read | Read | App from `app` | app |  | none | n/a | n/a |  |  |  | yes |  |
| `app.stop` | Safe | Safe | App from `app` | app |  | none | app ID | none |  |  |  | yes | quotable; always exact |
| `approver.add` | admin | n/a |  | name, sshPub |  | none | n/a | n/a |  |  |  | yes |  |
| `approver.remove` | admin | n/a |  | name |  | none | n/a | n/a |  |  |  | yes |  |
| `ask.batch` | live | SideEffect | Host | shape, ops (members) |  | always | each member's bound inputs; the member H list | per member |  |  |  | yes |  |
| `ask.quote` | read | Read | Host | ops (members) |  | none | n/a | n/a |  |  |  | yes |  |
| `ask.status` | read | Read | Host | id?, waitMs? |  | none | n/a | n/a |  |  |  |  |  |
| `budget.set` | admin | n/a |  | budgets |  | none | n/a | n/a |  |  |  | yes |  |
| `bus.agents.list` | read | Read | Host |  |  | none | n/a | n/a |  |  |  |  |  |
| `bus.inbox.ack` | coordination | Coordination | Inbox | messageId |  | none | n/a | none |  |  |  |  |  |
| `bus.inbox.read` | read | Coordination | Inbox |  |  | none | n/a | n/a |  |  |  |  |  |
| `bus.lease.acquire` | coordination | Coordination | Lease from `resource` | resource, ttlMs |  | none | n/a | none |  |  |  |  |  |
| `bus.lease.heartbeat` | coordination | Coordination | Lease from `resource` | resource, epoch, ttlMs |  | none | n/a | none |  |  |  |  |  |
| `bus.lease.release` | coordination | Coordination | Lease from `resource` | resource, epoch |  | none | n/a | none |  |  |  |  |  |
| `bus.message.send` | coordination | Coordination | Inbox from `to` | to, taskId?, parts |  | none | n/a | none |  |  |  |  |  |
| `bus.task.cancel` | coordination | Coordination | Task from `taskId` | taskId |  | none | n/a | none |  |  |  |  |  |
| `bus.task.claim` | coordination | Coordination | Task from `taskId` | taskId |  | none | n/a | none |  |  |  | yes |  |
| `bus.task.get` | read | Coordination | Task from `taskId` | taskId |  | none | n/a | n/a |  |  |  |  |  |
| `bus.task.send` | coordination | Coordination | Agent from `to` | to?, skills?, message, deadline?, asks? |  | none | n/a | none |  |  |  | yes |  |
| `bus.task.update` | coordination | Coordination | Task from `taskId` | taskId, state, message?, artifacts? |  | none | n/a | none |  |  |  |  |  |
| `cache.purge` | admin | n/a |  | agent |  | none | n/a | n/a |  |  |  | yes |  |
| `disk.usage` | read | Read | Host |  |  | none | n/a | n/a |  |  |  | yes |  |
| `file.write` | live | SideEffect | Path from `path` | path, content (hash) |  | if tainted | content hash | CAS-revert | yes |  |  | yes | quotable; CAS binder |
| `gh.issue.comment` | live | SideEffect | Repo from `remote` | remote, number, body (hash) |  | always | body hash (op marker included); gh_node_id | none (external) |  |  |  | yes | quotable; always exact |
| `gh.issue.read` | read | Read | Host | remote, number | issue (hash) | none | n/a | n/a |  | yes |  | yes |  |
| `gh.pr.comment` | live | SideEffect | Repo from `remote` | remote, number, body (hash) |  | always | body hash (op marker included); gh_node_id | none (external) |  |  |  | yes | batch push+reply; quotable; always exact |
| `gh.pr.create` | live | SideEffect | Repo from `remote` | remote, head, base, title (hash), body (hash) |  | always | head OID; body hash (op marker included); gh_node_id | none (external) |  |  |  | yes | batch push+pr; quotable |
| `gh.pr.read` | read | Read | Host | remote, number | pr (hash) | none | n/a | n/a |  | yes |  | yes |  |
| `go.private.set` | admin | n/a |  | agent, patterns |  | none | n/a | n/a |  |  |  | yes |  |
| `memory.forget` | agentboxd | SideEffect | MemoryScope from `factId` | factId |  | if tainted | fact ID | logical | yes |  | yes |  | quotable; always exact |
| `memory.purge` | admin | n/a |  | factId |  | always | fact ID; body hash | none |  |  |  | yes |  |
| `memory.read` | read | Read | MemoryScope from `scope` | scope, query? |  | none | n/a | n/a |  |  |  |  |  |
| `memory.review` | admin | n/a |  | factId, decision, bodyHash |  | always | fact ID; body hash | none |  |  |  | yes |  |
| `memory.write` | agentboxd | SideEffect | MemoryScope from `scope` | scope, title (hash), body (hash), ttlDays? |  | if tainted | body hash | logical | yes |  | yes |  | quotable; always exact |
| `net.allow_domain` | live | SideEffect | Domain from `host` | host, port, reason, agent? |  | always | host:port; agent | none |  |  |  | yes | quotable; always exact |
| `op.resolve` | admin | n/a |  | id, outcome |  | none | n/a | n/a |  |  |  | yes |  |
| `os.generations` | read | Read | Host |  |  | none | n/a | n/a |  |  |  | yes |  |
| `os.pkg.install` | os | SideEffect | Package from `packages` | packages |  | always | closure + .deb hashes; base gen; dpkg-status hash; end state | full OS |  |  |  | yes | quotable; CAS binder |
| `os.pkg.remove` | os | SideEffect | Package from `packages` | packages |  | always | closure + .deb hashes; base gen; dpkg-status hash; end state | full OS |  |  |  | yes | quotable; CAS binder |
| `os.rollback` | os | SideEffect | Generation from `gen` | gen |  | always | gen ID | full OS |  |  |  | yes | quotable; always exact |
| `os.unit.disable` | os | SideEffect | Unit from `unit` | unit |  | always | unit name | full OS |  |  |  | yes | quotable; always exact |
| `os.unit.enable` | os | SideEffect | Unit from `unit` | unit |  | always | unit name | full OS |  |  |  | yes | quotable; always exact |
| `os.update` | os | SideEffect | Host (human only) |  |  | unless the closure is inside the signed update.policy delta | closure + .deb hashes; base; updatePolicyDigest | full OS |  |  |  | yes | CAS binder |
| `passkey.confirm` | admin | n/a |  | id |  | always | regId; credIdHash; coseKeyHash; createdAt | n/a |  |  |  | yes |  |
| `passkey.register` | admin | n/a |  | name |  | none | n/a | n/a |  |  |  | yes |  |
| `passkey.revoke` | admin | n/a |  | id |  | none | n/a | n/a |  |  |  | yes |  |
| `pending.deny` | admin | n/a |  | id, strike? |  | none | n/a | n/a |  |  |  | yes |  |
| `pkg.search` | read | Read | Host | query |  | none | n/a | n/a |  |  |  | yes |  |
| `policy.set` | admin | n/a |  | policy |  | none | n/a | n/a |  |  |  | yes |  |
| `procedural.set` | admin | n/a |  | body |  | none | n/a | n/a |  |  |  | yes |  |
| `push.policy.set` | admin | n/a |  | remote, policy |  | none | n/a | n/a |  |  |  | yes |  |
| `remote.set` | admin | n/a |  | id, url |  | none | n/a | n/a |  |  |  | yes |  |
| `repo.create` | Safe | Safe | Host, Repo | name |  | none | n/a | none |  |  |  | yes | quotable; always exact |
| `repo.merge` | live | SideEffect | Repo from `p` | p, srcOid, dstOid |  | always | source and target OIDs | revert commit |  |  |  | yes | quotable |
| `repo.push` | live | SideEffect | Repo from `remote` | remote, ref, oid |  | unless a standing push policy covers a private remote and the task is clean | OID; remote_url; gh_node_id | none |  |  |  | yes | batch push+pr, push+reply; quotable |
| `secret.set` | admin | n/a |  | name, value (drop) |  | none | n/a | n/a |  |  |  | yes |  |
| `system.info` | read | Read | Host |  |  | none | n/a | n/a |  |  |  | yes |  |
| `taint.clear` | admin | n/a |  | subject, contentId |  | always | contentId; the subject's taint epoch; for workspace: the dependency report's SHA-256 and its high-risk count | none |  |  |  | yes |  |
| `update.policy.set` | admin | n/a |  | policy |  | none | n/a | n/a |  |  |  | yes |  |
| `workbench.add_package` | os | SideEffect | Package from `package` | package |  | always | closure + .deb hashes; base gen | full OS |  |  |  | yes | quotable; CAS binder |
| `workspace.restore` | live | SideEffect | WorkspaceSnap from `id` | id |  | always | snapshot ID; snapshot taint; tree digest; diff digest vs current | workspace | yes |  |  | yes | quotable |
| `workspace.snapshot` | Safe | Safe | Host, Repo |  |  | none | n/a | none |  |  |  | yes | quotable; always exact |
