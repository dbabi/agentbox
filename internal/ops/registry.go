// Package ops is the one operation registry (ARCHITECTURE.md §5.1, §5.3): every op is declared once here, and the Cedar
// schema, the JSON schemas, the MCP tool descriptors and the docs table are generated from it (`go generate`). rootd and
// agentboxd run Check at startup and refuse to start when the generated files on the box don't match this table.
package ops

// Class is the op's floor class, the §5.3 "Class" column.
type Class string

const (
	Read      Class = "read"
	Coord     Class = "coordination"
	Safe      Class = "Safe"
	Live      Class = "live"
	OS        Class = "os"
	Agentboxd Class = "agentboxd" // memory.write and memory.forget: agentboxd's own floor (§8)
	Admin     Class = "admin"     // humans on rootd-admin.sock, authorized by SO_PEERCRED; not Cedar-gated
)

// Group is the Cedar parent action (Appendix D). Admin ops have none.
type Group string

const (
	GRead       Group = "Read"
	GSafe       Group = "Safe"
	GSideEffect Group = "SideEffect"
	GCoord      Group = "Coordination"
)

// Sig is the signature requirement.
type Sig string

const (
	SigNone    Sig = "none"
	SigTainted Sig = "if tainted"
	SigChanged Sig = "if the manifest or exposure changes, or tainted"
	SigAlways  Sig = "always"
	SigPolicy  Sig = "unless a standing push policy covers a private remote and the task is clean"
)

// Coverage is the rollback coverage, the §5.3 "Rollback coverage" column.
type Coverage string

const (
	CovNA       Coverage = "n/a"
	CovNone     Coverage = "none"
	CovExternal Coverage = "none (external)"
	CovLogical  Coverage = "logical"
	CovWS       Coverage = "workspace"
	CovCAS      Coverage = "CAS-revert"
	CovOS       Coverage = "full OS"
	CovImage    Coverage = "previous image"
	CovRevert   Coverage = "revert commit"
	CovMember   Coverage = "per member"
)

// Audit is a field's audit class (§9): keep is logged verbatim, hash becomes {sha256, len}, drop is removed.
type Audit string

const (
	Keep Audit = "keep"
	Hash Audit = "hash"
	Drop Audit = "drop"
)

// Field is one arg or output. Type is a JSON schema type.
type Field struct {
	Name  string
	Type  string
	Opt   bool
	Audit Audit
}

func str(n string) Field        { return Field{Name: n, Type: "string", Audit: Keep} }
func num(n string) Field        { return Field{Name: n, Type: "integer", Audit: Keep} }
func list(n string) Field       { return Field{Name: n, Type: "array", Audit: Keep} }
func obj(n string) Field        { return Field{Name: n, Type: "object", Audit: Keep} }
func (f Field) opt() Field      { f.Opt = true; return f }
func (f Field) hash() Field     { f.Audit = Hash; return f }
func (f Field) drop() Field     { f.Audit = Drop; return f }
func fields(f ...Field) []Field { return f }

// Op is one registry entry.
type Op struct {
	Name  string
	Desc  string // the MCP tool description after the ask-cost line
	Class Class
	Group Group
	Human bool // principal Human only (os.update); otherwise Agent and Human

	// Resource builder: the Cedar entity types and the arg the resource is resolved from ("" = the Host, or the caller).
	Resource     []string
	ResourceFrom string

	Args, Out []Field
	Bound     []string // the immutable-input binder: what goes into H
	Sig       Sig
	Rollback  Coverage

	Reversible        bool // the only input to phone eligibility (§5.4)
	TaintsOutput      bool // a read whose output agentbox doesn't generate (§5.3)
	WorkspaceBindable bool // §8
	Rootd             bool // reaches rootd; false means agentboxd alone executes it
}

var (
	host   = []string{"Host"}
	app    = []string{"App"}
	repo   = []string{"Repo"}
	task   = []string{"Task"}
	lease  = []string{"Lease"}
	inbox  = []string{"Inbox"}
	mscope = []string{"MemoryScope"}
)

func rd(name, desc string, res []string, from string, args ...Field) Op {
	return Op{Name: name, Desc: desc, Class: Read, Group: GRead, Resource: res, ResourceFrom: from, Args: args, Sig: SigNone, Rollback: CovNA, Rootd: true}
}

func coord(name, desc string, res []string, from string, args ...Field) Op {
	return Op{Name: name, Desc: desc, Class: Coord, Group: GCoord, Resource: res, ResourceFrom: from, Args: args, Sig: SigNone, Rollback: CovNone}
}

func admin(name string, sig Sig, args ...Field) Op {
	return Op{Name: name, Class: Admin, Args: args, Sig: sig, Rollback: CovNA, Rootd: true}
}

func agentboxd(o Op) Op { o.Rootd = false; return o }

func taints(o Op, out ...Field) Op { o.TaintsOutput, o.Out = true, out; return o }

// Registry is every op in §5.3, sorted by name for review; generation sorts again.
var Registry = []Op{
	admin("agent.add", SigNone, str("name")),
	admin("agent.attach", SigNone, str("name"), str("workspace")),
	admin("agent.remove", SigNone, str("name")),
	admin("agent.skills.set", SigNone, str("agent"), list("skills")),
	{Name: "app.deploy", Desc: "Build and deploy one of your registered apps from its context, offline, from CAS.", Class: Live, Group: GSideEffect,
		Resource: app, ResourceFrom: "app", Args: fields(str("app"), str("context")), Bound: []string{"CAS digest", "base digest", "manifest hash"},
		Sig: SigChanged, Rollback: CovImage, Rootd: true},
	taints(rd("app.logs", "Read the redacted logs of one of your apps. The output taints this task.", app, "app", str("app"), num("lines").opt()),
		list("log").hash()),
	{Name: "app.remove", Desc: "Remove one of your registered apps.", Class: Live, Group: GSideEffect, Resource: app, ResourceFrom: "app",
		Args: fields(str("app")), Bound: []string{"app ID"}, Sig: SigAlways, Rollback: CovImage, Rootd: true},
	{Name: "app.restart", Desc: "Restart one of your registered apps.", Class: Safe, Group: GSafe, Resource: app, ResourceFrom: "app",
		Args: fields(str("app")), Bound: []string{"app ID"}, Sig: SigNone, Rollback: CovNone, Rootd: true},
	{Name: "app.rollback", Desc: "Roll one of your apps back to a kept image digest.", Class: Live, Group: GSideEffect, Resource: app, ResourceFrom: "app",
		Args: fields(str("app"), str("imageDigest")), Bound: []string{"app ID", "image digest"}, Sig: SigAlways, Rollback: CovImage, Rootd: true},
	{Name: "app.start", Desc: "Start one of your registered apps.", Class: Safe, Group: GSafe, Resource: app, ResourceFrom: "app",
		Args: fields(str("app")), Bound: []string{"app ID"}, Sig: SigNone, Rollback: CovNone, Rootd: true},
	rd("app.status", "Show the status of an app.", app, "app", str("app")),
	{Name: "app.stop", Desc: "Stop one of your registered apps.", Class: Safe, Group: GSafe, Resource: app, ResourceFrom: "app",
		Args: fields(str("app")), Bound: []string{"app ID"}, Sig: SigNone, Rollback: CovNone, Rootd: true},
	admin("approver.add", SigNone, str("name"), str("sshPub")),
	admin("approver.remove", SigNone, str("name")),
	{Name: "ask.batch", Desc: "Submit a push and its PR, or a push and its replies to one PR, as one ask.", Class: Live, Group: GSideEffect,
		Resource: host, Args: fields(str("shape"), list("ops")), Bound: []string{"each member's bound inputs", "the member H list"},
		Sig: SigAlways, Rollback: CovMember, Rootd: true},
	rd("ask.quote", "Quote what 1 to 8 ops would cost this task before acting. Quote your whole plan once.", host, "", list("ops")),
	agentboxd(rd("ask.status", "Show this task's asks and taint; with id, that ask's state. waitMs (at most 25000) waits for a change.", host, "",
		str("id").opt(), num("waitMs").opt())),
	agentboxd(rd("bus.agents.list", "List the agents on this box and their skills.", host, "")),
	agentboxd(Op{Name: "bus.inbox.ack", Desc: "Acknowledge a message in your inbox.", Class: Coord, Group: GCoord, Resource: inbox,
		Args: fields(str("messageId")), Sig: SigNone, Rollback: CovNone}),
	agentboxd(Op{Name: "bus.inbox.read", Desc: "Read your inbox. Tainted messages taint this task first.", Class: Read, Group: GCoord, Resource: inbox,
		Sig: SigNone, Rollback: CovNA}),
	coord("bus.lease.acquire", "Acquire an advisory lease (repo:<p>:main).", lease, "resource", str("resource"), num("ttlMs")),
	coord("bus.lease.heartbeat", "Extend a lease you hold.", lease, "resource", str("resource"), num("epoch"), num("ttlMs")),
	coord("bus.lease.release", "Release a lease you hold.", lease, "resource", str("resource"), num("epoch")),
	coord("bus.message.send", "Send a message to an agent linked to you by a live task.", inbox, "to", str("to"), str("taskId").opt(), list("parts")),
	agentboxd(Op{Name: "bus.task.cancel", Desc: "Cancel a task you originated.", Class: Coord, Group: GCoord, Resource: task, ResourceFrom: "taskId",
		Args: fields(str("taskId")), Sig: SigNone, Rollback: CovNone}),
	func() Op {
		o := coord("bus.task.claim", "Claim a task from the skills board, or one sent to you.", task, "taskId", str("taskId"))
		o.Rootd = true // rootd records the delegation capability at a skills: claim (§7)
		return o
	}(),
	agentboxd(Op{Name: "bus.task.get", Desc: "Get a task you execute or originated. A tainted child result taints this task first.", Class: Read,
		Group: GCoord, Resource: task, ResourceFrom: "taskId", Args: fields(str("taskId")), Sig: SigNone, Rollback: CovNA}),
	func() Op {
		o := coord("bus.task.send", "Delegate a task to an agent (to) or to the skills board (skills).", []string{"Agent"}, "to",
			str("to").opt(), list("skills").opt(), obj("message"), num("deadline").opt(), num("asks").opt())
		o.Rootd = true // rootd writes the delegations row
		return o
	}(),
	coord("bus.task.update", "Update the state, messages or artifacts of a task you execute.", task, "taskId",
		str("taskId"), str("state"), obj("message").opt(), list("artifacts").opt()),
	admin("budget.set", SigNone, str("budgets")),
	admin("cache.purge", SigNone, str("agent")),
	rd("disk.usage", "Show disk usage and quotas.", host, ""),
	{Name: "file.write", Desc: "Write a file under /srv/<your app>/.", Class: Live, Group: GSideEffect, Resource: []string{"Path"}, ResourceFrom: "path",
		Args: fields(str("path"), str("content").hash()), Bound: []string{"content hash"}, Sig: SigTainted, Rollback: CovCAS, Reversible: true, Rootd: true},
	taints(rd("gh.issue.read", "Read a GitHub issue on one of your remotes. The output taints this task.", host, "", str("remote"), num("number")),
		obj("issue").hash()),
	{Name: "gh.issue.comment", Desc: "Comment on a GitHub issue on one of your remotes.", Class: Live, Group: GSideEffect, Resource: repo, ResourceFrom: "remote",
		Args: fields(str("remote"), num("number"), str("body").hash()), Bound: []string{"body hash (op marker included)", "gh_node_id"},
		Sig: SigAlways, Rollback: CovExternal, Rootd: true},
	{Name: "gh.pr.comment", Desc: "Comment on a pull request on one of your remotes.", Class: Live, Group: GSideEffect, Resource: repo, ResourceFrom: "remote",
		Args: fields(str("remote"), num("number"), str("body").hash()), Bound: []string{"body hash (op marker included)", "gh_node_id"},
		Sig: SigAlways, Rollback: CovExternal, Rootd: true},
	{Name: "gh.pr.create", Desc: "Open a pull request from a pushed agent/<you>/* ref.", Class: Live, Group: GSideEffect, Resource: repo, ResourceFrom: "remote",
		Args:  fields(str("remote"), str("head"), str("base"), str("title").hash(), str("body").hash()),
		Bound: []string{"head OID", "body hash (op marker included)", "gh_node_id"}, Sig: SigAlways, Rollback: CovExternal, Rootd: true},
	taints(rd("gh.pr.read", "Read a pull request on one of your remotes. The output taints this task.", host, "", str("remote"), num("number")),
		obj("pr").hash()),
	admin("go.private.set", SigNone, str("agent"), str("patterns")),
	agentboxd(Op{Name: "memory.forget", Desc: "Forget a fact you could read now.", Class: Agentboxd, Group: GSideEffect, Resource: mscope, ResourceFrom: "factId",
		Args: fields(str("factId")), Bound: []string{"fact ID"}, Sig: SigTainted, Rollback: CovLogical, Reversible: true, WorkspaceBindable: true}),
	admin("memory.purge", SigAlways, str("factId")),
	agentboxd(rd("memory.read", "Read facts from a memory scope. Tainted facts taint this task first.", mscope, "scope", str("scope"), str("query").opt())),
	admin("memory.review", SigAlways, str("factId"), str("decision"), str("bodyHash")),
	agentboxd(Op{Name: "memory.write", Desc: "Write a fact to a memory scope.", Class: Agentboxd, Group: GSideEffect, Resource: mscope, ResourceFrom: "scope",
		Args: fields(str("scope"), str("title").hash(), str("body").hash(), num("ttlDays").opt()), Bound: []string{"body hash"},
		Sig: SigTainted, Rollback: CovLogical, Reversible: true, WorkspaceBindable: true}),
	{Name: "net.allow_domain", Desc: "Ask a human to add host:port to your egress list.", Class: Live, Group: GSideEffect, Resource: []string{"Domain"},
		ResourceFrom: "host", Args: fields(str("host"), num("port"), str("reason"), str("agent").opt()), Bound: []string{"host:port", "agent"},
		Sig: SigAlways, Rollback: CovNone, Rootd: true},
	admin("op.resolve", SigNone, str("id"), str("outcome")),
	rd("os.generations", "List the OS generations.", host, ""),
	{Name: "os.pkg.install", Desc: "Install Ubuntu packages into a new OS generation.", Class: OS, Group: GSideEffect, Resource: []string{"Package"},
		ResourceFrom: "packages", Args: fields(list("packages")), Bound: []string{"closure + .deb hashes", "base gen", "dpkg-status hash", "end state"},
		Sig: SigAlways, Rollback: CovOS, Rootd: true},
	{Name: "os.pkg.remove", Desc: "Remove Ubuntu packages in a new OS generation.", Class: OS, Group: GSideEffect, Resource: []string{"Package"},
		ResourceFrom: "packages", Args: fields(list("packages")), Bound: []string{"closure + .deb hashes", "base gen", "dpkg-status hash", "end state"},
		Sig: SigAlways, Rollback: CovOS, Rootd: true},
	{Name: "os.rollback", Desc: "Roll the OS back to a kept generation.", Class: OS, Group: GSideEffect, Resource: []string{"Generation"},
		ResourceFrom: "gen", Args: fields(num("gen")), Bound: []string{"gen ID"}, Sig: SigAlways, Rollback: CovOS, Rootd: true},
	{Name: "os.unit.disable", Desc: "Disable a systemd unit in a new OS generation.", Class: OS, Group: GSideEffect, Resource: []string{"Unit"},
		ResourceFrom: "unit", Args: fields(str("unit")), Bound: []string{"unit name"}, Sig: SigAlways, Rollback: CovOS, Rootd: true},
	{Name: "os.unit.enable", Desc: "Enable a systemd unit in a new OS generation.", Class: OS, Group: GSideEffect, Resource: []string{"Unit"},
		ResourceFrom: "unit", Args: fields(str("unit")), Bound: []string{"unit name"}, Sig: SigAlways, Rollback: CovOS, Rootd: true},
	{Name: "os.update", Class: OS, Group: GSideEffect, Human: true, Resource: host,
		Bound: []string{"closure + .deb hashes", "base", "updatePolicyDigest"}, Sig: SigAlways, Rollback: CovOS, Rootd: true},
	admin("passkey.confirm", SigAlways, str("id")),
	admin("passkey.register", SigNone, str("name")),
	admin("passkey.revoke", SigNone, str("id")),
	admin("pending.deny", SigNone, str("id"), list("strike").opt()),
	rd("pkg.search", "Search the Ubuntu archive for packages.", host, "", str("query")),
	admin("policy.set", SigNone, str("policy")),
	admin("procedural.set", SigNone, str("body")),
	admin("push.policy.set", SigNone, str("remote"), str("policy")),
	admin("remote.set", SigNone, str("id"), str("url")),
	{Name: "repo.create", Desc: "Create a local git repo.", Class: Safe, Group: GSafe, Resource: []string{"Host", "Repo"},
		Args: fields(str("name")), Sig: SigNone, Rollback: CovNone, Rootd: true},
	{Name: "repo.merge", Desc: "Merge a branch into a local repo's main.", Class: Live, Group: GSideEffect, Resource: repo, ResourceFrom: "p",
		Args: fields(str("p"), str("srcOid"), str("dstOid")), Bound: []string{"source and target OIDs"}, Sig: SigAlways, Rollback: CovRevert, Rootd: true},
	{Name: "repo.push", Desc: "Push an agent/<you>/* ref to one of your registered remotes.", Class: Live, Group: GSideEffect, Resource: repo, ResourceFrom: "remote",
		Args: fields(str("remote"), str("ref"), str("oid")), Bound: []string{"OID", "remote_url", "gh_node_id"}, Sig: SigPolicy, Rollback: CovNone, Rootd: true},
	admin("secret.set", SigNone, str("name"), str("value").drop()),
	rd("system.info", "Show box and release information.", host, ""),
	admin("taint.clear", SigAlways, str("subject"), str("contentId")),
	admin("update.policy.set", SigNone, str("policy")),
	{Name: "workbench.add_package", Desc: "Add an Ubuntu package to your workbench image.", Class: OS, Group: GSideEffect, Resource: []string{"Package"},
		ResourceFrom: "package", Args: fields(str("package")), Bound: []string{"closure + .deb hashes", "base gen"}, Sig: SigAlways, Rollback: CovOS, Rootd: true},
	{Name: "workspace.restore", Desc: "Restore your workspace from one of its snapshots.", Class: Live, Group: GSideEffect, Resource: []string{"WorkspaceSnap"},
		ResourceFrom: "id", Args: fields(str("id")), Bound: []string{"snapshot ID", "snapshot taint", "tree digest", "diff digest vs current"},
		Sig: SigAlways, Rollback: CovWS, Reversible: true, Rootd: true},
	{Name: "workspace.snapshot", Desc: "Take a read-only snapshot of your workspace.", Class: Safe, Group: GSafe, Resource: []string{"Host", "Repo"},
		Sig: SigNone, Rollback: CovNone, Rootd: true},
}

// cedarHead is the hand-kept part of the Cedar schema (Appendix D): the context type and the entity types. The actions
// are generated from Registry.
const cedarHead = `  type Ctx = { approved: Bool, tainted: Bool, workspaceBound: Bool, riskEscalated: Bool, hop: Long, budgetLeftCents: Long, executor: Agent };
  entity Human; entity Agent { skills: Set<String> }; entity Host; entity Domain; entity Repo; entity Generation; entity WorkspaceSnap;
  entity Lease { holder?: Agent };
  entity App { owner: Agent, manifestChanged: Bool, exposureChanged: Bool };
  entity Path { path: String, app?: App };
  entity Package { name: String };
  entity Unit { name: String };
  entity MemoryScope { kind: String, owner?: Agent };
  entity Task { executor?: Agent, skill?: String, originatorAgent?: Agent, originatorHuman?: Human };
  entity Inbox { owner: Agent, peers: Set<Agent> };
`
