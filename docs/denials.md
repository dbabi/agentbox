<!-- Code generated from internal/ops/registry.go by go generate; DO NOT EDIT. -->
# Denial codes

Every code an agent can see, from `internal/ops/codes.go` (ARCHITECTURE.md §5.6). This is also the `agentbox why` text. Codes are append-only.

| Code | next | By | HTTP | Message | what (next) | Remedy | Notes |
|---|---|---|---|---|---|---|---|
| `INVALID_ARGS` | fix | gate, floor | 400 | {op} has an invalid argument: fix the field named in remedy. |  | fix | `field` (JSON pointer) and `expect`; never the value; also a body that contains `agentbox-op:` |
| `UNKNOWN_OP` | stop | gate | 400 | This op does not exist or no agent may call it. |  | none | also any op no agent may call |
| `TASK_ENDED` | stop | gate, cedar, floor, proxy, keys, git, forwarder | 409 | This task has ended. |  | none |  |
| `NOT_FOUND_OR_NOT_OWNED` | stop | gate, cedar, floor, git | 404 | {op}: no such item among yours. |  | none | one path (§5.2); at receipt + 200 ms |
| `DENIED_POLICY` | stop | cedar | 403 | {op} is denied by policy. |  | none | `rule` per leak rule 5 |
| `POLICY_ERROR` | human | cedar | 500 | Policy evaluation failed, so {op} is denied. |  | human{agentbox policy check} | evaluation error; fails closed |
| `MEMORY_QUARANTINED` | human | gate | 202 | The fact was stored in quarantine; a human may release it. |  | human{agentbox memory review} | the write was stored in quarantine; MCP `isError: false` |
| `CAP_REACHED` | human | gate, floor, git, keys, proxy | 429 | {op} is over a cap of {limit}. | `memory_writes_task` (human), `memory_rows` (human), `memory_bytes` (human), `bus_messages` (human), `artifacts` (human), `push_bytes_day` (human), `quote_items_task` (stop), `quote_items_trace` (stop), `body_bytes` (fix), `decoded_bytes` (fix), `header_bytes` (fix), `header_timeout` (retry), `read_timeout` (retry), `connections` (retry) | human{agentbox budget set} | broker admission (#115): `body_bytes` and `decoded_bytes` (413), `header_bytes` (431), `header_timeout` and `read_timeout` (408), `connections` (429) per task |
| `BUS_REFUSED` | stop | gate | 409 | {op} is refused by a bus limit. | `hop` (stop), `children` (stop), `cycle` (stop), `deadline` (stop), `parent_ended` (stop), `not_cancelable` (stop) | none |  |
| `LEASE_HELD` | retry | gate | 409 | The lease is held; retry after {afterMs} ms. |  | retry | `afterMs` 30000; never names the holder |
| `NEEDS_SIGNATURE` | wait | floor | 202 | {op} waits for a human ({channel}) until {time}. It stays open if your task ends normally. Run: agentbox ask wait {id}. |  | wait, poll | see Asks; at receipt + 2 s |
| `ASK_DENIED` | stop | floor | 403 | A human denied this ask in this task; do not ask again. |  | none | a human denied this match key in this task; carries the denied row's id |
| `ASK_EXPIRED` | ask | floor | 410 | The ask for {op} expired; a new ask counts against your budget. |  | op |  |
| `ASK_CAP` | human | floor | 429 | {op} is over an ask cap. | `task_open` (wait), `task_budget` (human), `agent_24h` (human), `agent_ops_24h` (human) | human{agentbox budget set} |  |
| `STALE` | human | floor | 409 | {op} is stale: what it was bound to has changed. | `ref_moved` (fix), `cas_changed` (fix), `stale_base` (fix), `policy_changed` (ask), `signer_revoked` (ask), `approval_expired` (ask), `taint_moved` (wait), `remote_changed` (human) | human{agentbox task show} |  |
| `BUSY` | retry | floor | 503 | The box is busy; retry after {afterMs} ms. |  | retry | OS lock, box CAS-binding cap, disk reserve, box daemon-ask pool; no sub-reason |
| `ADMISSION_REJECTED` | fix | floor | 400 | {op} is refused at admission. | `closure_too_large` (fix), `context_too_large` (fix), `own_cas_pending` (wait), `batch_shape` (fix), `batch_remote_not_private` (fix), `batch_text_cap` (fix), `batch_member_open` (fix), `batch_open` (wait) | fix |  |
| `FLOOR_NEVER` | stop | floor | 403 | {op} is never allowed on this box. | `protected_package` (stop), `protected_unit` (stop), `exposure_443` (stop), `vendor_host` (stop), `never_available` (stop) | none | `never_available`: an op this floor never runs (no effect in this release, or one the gate should have refused) |
| `HUMAN_ONLY` | human | floor | 403 | Only a human can do this. | `deputy_host` (human) | human{agentbox egress allow} |  |
| `REF_OUTSIDE_NAMESPACE` | fix | floor, git | 403 | Push only refs under refs/heads/agent/<your name>/. |  | fix | expect `refs/heads/agent/<name>/*` |
| `OID_NOT_IN_REMOTE_REPO` | fix | floor | 400 | The commit is not in the remote repo: push it through :8082 first. |  | fix |  |
| `REMOTE_REJECTED` | human | floor | 502 | The remote refused {op}. | `pr_exists` (fix), `no_commits` (fix), `ruleset` (stop), `not_found` (human), `other` (human), `rate_limited` (retry), `unreachable` (retry) | human{agentbox task show} | no GitHub text or status |
| `EFFECT_FAILED` | human | floor | 500 | {op} failed while running. |  | human{agentbox task show} | no effect output |
| `INDETERMINATE` | human | floor | 500 | It is unknown whether {op} took effect; a human resolves it. |  | human{agentbox op resolve} |  |
| `BATCH_ABORTED` | ask | floor | 409 | An earlier member of the batch failed or was refused; {op} never ran. |  | op |  |
| `NESTED_SUBVOLUME` | human | floor | 409 | The workspace holds a nested subvolume, so {op} is refused. |  | human{agentbox workspace check} | name kept from §4.1 |
| `AUDIT_UNAVAILABLE` | retry | floor, proxy, keys, git | 503 | The audit log is unavailable; retry after {afterMs} ms. |  | retry | auditd down or in disk-full mode |
| `EGRESS_NOT_ALLOWLISTED` | ask | proxy | 403 | This host:port is not on your egress list. | `deputy_host` (human) | op | remedy `net.allow_domain{host, port}`, CLI; for a deputy host, `human{agentbox egress allow}` |
| `EGRESS_WRONG_ROUTE` | fix | proxy | 400 | Wrong route for this request. | `llm_vendor` (fix), `plain_http` (fix) | fix | `llm_vendor` (use `:8081`), `plain_http` |
| `EGRESS_NAME_REJECTED` | stop | proxy | 403 | This name does not resolve to a public address. | `non_public` (stop) | none | `non_public` only; no IP, no check name |
| `EGRESS_RESOLVE_FAILED` | retry | proxy | 502 | The name could not be resolved. | `no_such_name` (fix), `unavailable` (retry) | retry |  |
| `EGRESS_DIAL_FAILED` | retry | proxy | 504 | The connection to the host failed; retry after {afterMs} ms. | `timeout` (retry), `refused` (retry), `blocked` (retry) | retry |  |
| `KEYS_REQUEST_REJECTED` | human | keys | 403 | The LLM request has a field this box does not allow. | `max_tokens` (fix), `server_tool` (fix), `dropped_field` (fix), `endpoint` (human), `field` (human), `block_type` (human), `tool_type` (human), `url_field` (human), `source_type` (human), `beta_header` (human), `model` (human) | human{agentbox task show} | 400 with the vendor's wording for `beta_header` (`capability_rejected: beta_header:<value>`) and a `field` outside the schema, so Claude Code retries without them (#18) |
| `KEYS_BUDGET` | human | keys | 429 | Your LLM budget is spent. | `agent` (human), `trace` (human) | human{agentbox budget set} | own day share or trace only |
| `KEYS_UPSTREAM` | retry | keys | 502 | The LLM vendor could not be reached. | `unreachable` (retry), `timeout` (retry), `auth` (human), `reflect` (human) | retry | `reflect`: the vendor's reply held the injected key, raw or encoded; none of it reached the task (#18) |
| `BROKER_UNAVAILABLE` | retry | forwarder | 503 | A box service is unavailable; retry after {afterMs} ms. | `gate` (retry), `egress` (retry), `llm` (retry), `git` (retry) | retry | also a gate reply that fails the in-task check |
| `EXFIL_CANARY` | human | git, floor, gate | 403 | {op} was refused: it carries a credential planted in this task, and a human was alerted. |  | human{agentbox task show} | the canary in raw, base64, hex or split form; the task is tainted |
