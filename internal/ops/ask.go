package ops

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"agentbox/internal/ids"
)

// Batch shapes and caps (ARCHITECTURE.md §5.1 Batch check, §5.2 Batches).
const (
	ShapePushPR    = "push+pr"
	ShapePushReply = "push+reply"

	BatchMemberText = 16 << 10 // agent-controlled text per member
	BatchText       = 64 << 10 // per batch
	BatchMaxReplies = 3        // gh.pr.comment members of a push+reply
	QuoteMaxItems   = 8
)

// Shapes is every ask.batch shape: its member ops in order, and whether its remote must be private.
var Shapes = map[string]struct {
	Members []string
	Private bool
}{
	ShapePushPR:    {[]string{"repo.push", "gh.pr.create"}, false},
	ShapePushReply: {[]string{"repo.push", "gh.pr.comment"}, true}, // the comment repeats 1 to BatchMaxReplies times
}

var batchRoles = map[string][]string{
	"repo.push":     {ShapePushPR, ShapePushReply},
	"gh.pr.create":  {ShapePushPR},
	"gh.pr.comment": {ShapePushReply},
}

// exactOps: ops whose quote skips no check (§5.2 Quotes skips decide, resolution, GitHub, osbuild-fetch, file and repo
// reads, binder writes). Their cost follows from args, the caller's taint and DB rows alone. Every other quotable op
// reads something a quote skips: repo.push and repo.merge read git/, file.write /srv, app.deploy the context, os.pkg.*
// and workbench.add_package need osbuild-fetch, gh.pr.create checks the head OID in the remote repo, and
// workspace.restore digests the tree.
var exactOps = []string{"app.remove", "app.restart", "app.rollback", "app.start", "app.stop", "gh.issue.comment", "gh.pr.comment",
	"memory.forget", "memory.write", "net.allow_domain", "os.rollback", "os.unit.disable", "os.unit.enable", "repo.create", "workspace.snapshot"}

// casBinders: ops whose binding admission writes CAS objects (§5.2 Binding admission).
var casBinders = []string{"app.deploy", "file.write", "os.pkg.install", "os.pkg.remove", "os.update", "workbench.add_package"}

// quotableRule is §5.1's quote check: every Safe, live and os op an agent may submit, plus memory.write and
// memory.forget. ask.batch is the container a quote prices with 2 or more items, never an item itself.
func quotableRule(o Op) bool {
	agent := o.Group != "" && !o.Human
	return agent && o.Name != "ask.batch" && (slices.Contains([]Class{Safe, Live, OS}, o.Class) || o.Name == "memory.write" || o.Name == "memory.forget")
}

func withAskFields(reg []Op) []Op {
	for i := range reg {
		o := &reg[i]
		o.Batch = batchRoles[o.Name]
		o.Quotable = quotableRule(*o)
		o.Exact = slices.Contains(exactOps, o.Name)
		o.CASBinder = slices.Contains(casBinders, o.Name)
	}
	return reg
}

// The ask ops every agentbox build must have (D-G1).
var askOps = []string{"ask.quote", "ask.status", "ask.batch"}

// validateAsk is the batch and quote half of the startup check.
func validateAsk(reg []Op) []error {
	var errs []error
	byName := map[string]Op{}
	for _, o := range reg {
		byName[o.Name] = o
	}
	for _, n := range askOps {
		if o, ok := byName[n]; !ok || o.Group == "" || o.Human {
			errs = append(errs, fmt.Errorf("%s: missing from the registry, the Cedar schema or the MCP tools", n))
		}
	}
	members := map[string][]string{}
	for _, o := range reg {
		for _, s := range o.Batch {
			if _, ok := Shapes[s]; !ok {
				errs = append(errs, fmt.Errorf("%s: unknown batch shape %q", o.Name, s))
			}
			members[s] = append(members[s], o.Name)
		}
		if len(o.Batch) > 0 && (o.Reversible || o.CASBinder || o.Class != Live) {
			errs = append(errs, fmt.Errorf("%s: a batch member must be live, not reversible (no phone path) and write no CAS at admission", o.Name))
		}
		if o.Quotable != quotableRule(o) {
			errs = append(errs, fmt.Errorf("%s: quotable is every Safe, live and os op an agent may submit, plus memory.write and memory.forget", o.Name))
		}
		if o.Exact && !o.Quotable {
			errs = append(errs, fmt.Errorf("%s: always-exact but not quotable", o.Name))
		}
	}
	for s, sh := range Shapes {
		got, want := slices.Sorted(slices.Values(members[s])), slices.Sorted(slices.Values(sh.Members))
		if !slices.Equal(got, want) {
			errs = append(errs, fmt.Errorf("batch shape %s: members %v, want %v", s, got, want))
		}
	}
	return errs
}

// The ask.quote and ask.status replies (§5.2 Quotes, §5.3, §5.4 Budget view). Every field is an enum, an integer, a
// boolean or an id: no free text and no agent-wide value (D-G2).

// Asks is the task's own ask budget view.
type Asks struct {
	Max       int64 `json:"max"`
	Used      int64 `json:"used"`
	Granted   int64 `json:"granted"`
	Open      int64 `json:"open"`
	OpenBatch int64 `json:"openBatch"`
	Left      int64 `json:"left"`
}

type QuoteItem struct {
	Cost   string `json:"cost"`
	Reason string `json:"reason,omitempty"`
	Exact  bool   `json:"exact"`
	Shape  string `json:"shape,omitempty"`
}

type QuoteBatch struct {
	OK    bool   `json:"ok"`
	Shape string `json:"shape,omitempty"`
	Asks  int64  `json:"asks,omitempty"`
	What  string `json:"what,omitempty"` // the ADMISSION_REJECTED what ask.batch would return
}

type QuoteReply struct {
	Items []QuoteItem `json:"items"`
	Batch *QuoteBatch `json:"batch,omitempty"`
	Asks  Asks        `json:"asks"`
	Taint Taint       `json:"taint"`
}

// AskResult holds only agentbox-generated outputs (§5.3 Op outputs): never a GitHub-assigned number or URL.
type AskResult struct {
	OID     string `json:"oid,omitempty"`
	HeadOID string `json:"headOid,omitempty"`
	Digest  string `json:"digest,omitempty"`
	Gen     int64  `json:"gen,omitempty"`
	Remote  string `json:"remote,omitempty"`
}

type AskMember struct {
	Idx   int64  `json:"idx"`
	ID    string `json:"id"`
	Op    string `json:"op"`
	State string `json:"state"`
	Code  string `json:"code,omitempty"`
}

type AskRow struct {
	ID        string      `json:"id"`
	Op        string      `json:"op"`
	State     string      `json:"state"`
	Code      string      `json:"code,omitempty"`
	Channel   string      `json:"channel"`
	ExpiresAt int64       `json:"expiresAt"`
	Result    *AskResult  `json:"result,omitempty"`
	Members   []AskMember `json:"members,omitempty"`
}

type StatusReply struct {
	Asks  Asks     `json:"asks"`
	Taint Taint    `json:"taint"`
	Open  []string `json:"open"`
	Ask   *AskRow  `json:"ask,omitempty"`
}

var (
	quoteCosts   = []string{"run", "ask_phone", "ask_cli", "quarantine", "deny", "none"}
	quoteReasons = map[string][]string{"ask_phone": {"tainted", "signed", "unchecked"}, "ask_cli": {"tainted", "signed", "unchecked"},
		"quarantine": {"tainted", "shared_scope"}, "none": {"already_allowed"}, "run": {""}}
	askStates = []string{"pending", "approved", "executing", "executed", "refused", "failed", "indeterminate", "denied", "expired"}
	reDigest  = reOID // sha256 hex digests share the 64-hex form; a 40-hex SHA-1 OID is not a digest
)

// An ask's expiresAt is a Unix ms time from 2001 to 2100: a small number there could only be a smuggled one.
const minMs, maxMs = 1_000_000_000_000, 4_102_444_800_000

// resultFields are the agentbox-generated outputs an op's ask.status result may carry (§5.3 Op outputs). Any other
// field for that op is a channel a gate could put a GitHub-assigned number in.
func resultFields(op string) []string {
	switch {
	case op == "repo.push":
		return []string{"oid", "remote"}
	case op == "repo.merge":
		return []string{"oid"}
	case op == "gh.pr.create":
		return []string{"headOid"}
	case op == "ask.batch":
		return []string{"oid", "remote", "headOid"} // its repo.push and gh.pr.create members
	case strings.HasPrefix(op, "os."):
		return []string{"gen"}
	case op == "app.deploy", strings.HasPrefix(op, "workspace."):
		return []string{"digest"}
	}
	return nil
}

func resultFieldsDoc(reg []Op) map[string][]string {
	m := map[string][]string{}
	for _, o := range cedarOps(reg) {
		if f := resultFields(o.Name); f != nil {
			m[o.Name] = f
		}
	}
	return m
}

func strictDecode(b []byte, v any) error {
	if len(b) > 64<<10 || !printable(bytes.TrimRight(b, "\n")) {
		return errors.New("not printable ASCII of at most 64 KiB")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data")
	}
	return nil
}

func (a Asks) valid() bool {
	return a.Max >= 0 && a.Max <= 10 && a.Used >= 0 && a.Granted >= 0 && a.Open >= 0 && a.Open <= 3 && a.OpenBatch >= 0 &&
		a.OpenBatch <= a.Open && a.Left == max(0, min(a.Max-a.Used-a.Granted, 3-a.Open))
}

// CheckQuoteReply is the in-task check of an ask.quote reply for the n items quoted. It returns the reply re-encoded,
// so no byte of the gate's own encoding reaches the task.
func CheckQuoteReply(b []byte, n int) ([]byte, error) {
	var r QuoteReply
	if err := strictDecode(b, &r); err != nil {
		return nil, err
	}
	if len(r.Items) != n || n < 1 || n > QuoteMaxItems || !r.Asks.valid() {
		return nil, errors.New("item count or asks view")
	}
	for _, it := range r.Items {
		if !slices.Contains(quoteCosts, it.Cost) || it.Shape != "" && Shapes[it.Shape].Members == nil {
			return nil, errors.New("bad item")
		}
		if it.Cost == "deny" {
			if _, ok := LookupCode(it.Reason); !ok {
				return nil, errors.New("a deny item's reason is a §5.6 code")
			}
		} else if !slices.Contains(quoteReasons[it.Cost], it.Reason) {
			return nil, errors.New("bad reason for its cost")
		}
		if it.Cost == "run" && it.Reason != "" {
			return nil, errors.New("run has no reason")
		}
	}
	if (r.Batch != nil) != (n >= 2) {
		return nil, errors.New("batch is present exactly when 2 or more items are quoted")
	}
	if bt := r.Batch; bt != nil {
		var admission []string
		for _, x := range codeDefs["ADMISSION_REJECTED"].Whats {
			admission = append(admission, x.Name)
		}
		if bt.OK && (Shapes[bt.Shape].Members == nil || bt.Asks != 1 || bt.What != "") ||
			!bt.OK && (bt.Shape != "" || bt.Asks != 0 || !slices.Contains(admission, bt.What)) {
			return nil, errors.New("bad batch")
		}
	}
	return json.Marshal(r)
}

// CheckStatusReply is the in-task check of an ask.status reply.
func CheckStatusReply(b []byte) ([]byte, error) {
	var r StatusReply
	if err := strictDecode(b, &r); err != nil {
		return nil, err
	}
	if !r.Asks.valid() || r.Open == nil || len(r.Open) > 3 {
		return nil, errors.New("asks view or open list")
	}
	for _, id := range r.Open {
		if !ids.Is(ids.Pending, id) {
			return nil, errors.New("open id")
		}
	}
	if a := r.Ask; a != nil {
		o, ok := opDef(a.Op)
		if !ids.Is(ids.Pending, a.ID) || !ok || !slices.Contains(askStates, a.State) || a.Channel != channelOf(o) || a.ExpiresAt < minMs || a.ExpiresAt > maxMs {
			return nil, errors.New("bad ask row")
		}
		if _, ok := LookupCode(a.Code); a.Code != "" && !ok {
			return nil, errors.New("bad code")
		}
		if x := a.Result; x != nil {
			if x.OID != "" && !reOID.MatchString(x.OID) || x.HeadOID != "" && !reOID.MatchString(x.HeadOID) ||
				x.Digest != "" && !(reDigest.MatchString(x.Digest) && len(x.Digest) == 64) || x.Gen < 0 || x.Remote != "" && !reRemote.MatchString(x.Remote) {
				return nil, errors.New("bad result")
			}
			for k, set := range map[string]bool{"oid": x.OID != "", "headOid": x.HeadOID != "", "digest": x.Digest != "", "gen": x.Gen != 0, "remote": x.Remote != ""} {
				if set && !slices.Contains(resultFields(a.Op), k) {
					return nil, fmt.Errorf("result.%s is not an output of %s", k, a.Op)
				}
			}
		}
		if len(a.Members) > 1+BatchMaxReplies || len(a.Members) > 0 && a.Op != "ask.batch" {
			return nil, errors.New("members")
		}
		for i, m := range a.Members {
			mo, ok := opDef(m.Op)
			if m.Idx != int64(i) || !ids.Is(ids.Pending, m.ID) || !ok || len(mo.Batch) == 0 || !slices.Contains(askStates, m.State) {
				return nil, errors.New("bad member")
			}
			if _, ok := LookupCode(m.Code); m.Code != "" && !ok {
				return nil, errors.New("bad member code")
			}
		}
	}
	return json.Marshal(r)
}
