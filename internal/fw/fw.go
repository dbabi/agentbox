// Package fw loads and verifies the inet agentbox nftables table (ARCHITECTURE.md §6.1, Appendix B): the output chain
// that confines agentbox's own uids, and the default-drop input chain.
//
// Load is agentbox-firewall.service: one add-only nft -f transaction, then a check that the live table is the one the
// ruleset makes. Check is fwcheck: the normalized stateless hash, the static sets, the sets rootd fills (compared to
// rootd.db's set_elements rows, Appendix E), the reserved loopback ports and the masked nftables.service. Refill makes
// the exact sets (port_allow, allow_private*) match rootd.db; rootd runs it at start, before READY=1, next to its own
// dst set refill (internal/rootd/resolve).
package fw

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

const (
	RulesPath  = "/etc/nftables.d/agentbox.nft"
	SysctlPath = "/etc/sysctl.d/60-agentbox.conf"
	RootdDB    = "/var/lib/agentbox/rootd.db"
	// SSHFromPath lists the prefixes sshd accepts connections from, one per line (`agentbox seed --ssh-from`).
	SSHFromPath = "/etc/agentbox/ssh-from"
	// Reserved loopback service ports (§6.1): only (uid . port) tuples in port_allow may open them.
	ReservedLo, ReservedHi = 43000, 45999
	ElementTimeout         = 10 * time.Minute
	// ElementSlack is how long past its row's expiry a dst element may still be in the kernel: rootd computes the
	// expiry before nft adds the element. fwcheck accepts it, and rootd keeps the row that long.
	ElementSlack   = 5 * time.Second
	reservedSysctl = "/proc/sys/net/ipv4/ip_local_reserved_ports"
)

// The static sets. rootd never inserts into them; rootd's address checks (Appendix B) use Private4 and Private6 too,
// so the Go table and the nft sets come from this one list.
var (
	// every agent (70001-70999) and app (71001-71999) uid and the whole sub-id span 0x70000000-0x77FFFFFF (§4.1)
	Confined = []string{"70001-70999", "71001-71999", "1879048192-2013265919"}
	Private4 = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3"}
	Private6 = []string{"::/127", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32", "3fff::/20",
		"5f00::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8"}
)

// DefaultSSHFrom is the input chain's SSH sources on a box whose seed named none: the private LAN ranges, the tailnet's
// CGNAT range and link-local, so a box that gets the input chain in an update keeps its LAN SSH.
var DefaultSSHFrom = []string{"10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10"}

// ParseSSHFrom reads the ssh-from format: one prefix per line, blank lines and # comments skipped. It returns the
// canonical prefixes and refuses an empty list (no SSH but the console and tailscale0) and overlapping prefixes, which
// nft refuses in an interval set without auto-merge.
func ParseSSHFrom(b []byte) ([]netip.Prefix, error) {
	var ps []netip.Prefix
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		p, err := netip.ParsePrefix(l)
		if err != nil || p.Addr().Zone() != "" || p.Addr().Is4In6() {
			return nil, fmt.Errorf("ssh-from %q: not an IPv4 or IPv6 prefix", l)
		}
		p = p.Masked()
		for _, q := range ps {
			if q.Overlaps(p) {
				return nil, fmt.Errorf("ssh-from %s overlaps %s", p, q)
			}
		}
		ps = append(ps, p)
	}
	if len(ps) == 0 {
		return nil, errors.New("ssh-from: no prefix; SSH would be open to none")
	}
	return ps, nil
}

// SSHFrom reads SSHFromPath, or returns DefaultSSHFrom when it doesn't exist.
func SSHFrom() ([]netip.Prefix, error) {
	b, err := os.ReadFile(SSHFromPath)
	if errors.Is(err, os.ErrNotExist) {
		b, err = []byte(strings.Join(DefaultSSHFrom, "\n")), nil
	}
	if err != nil {
		return nil, err
	}
	ps, err := ParseSSHFrom(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", SSHFromPath, err)
	}
	return ps, nil
}

// sshSets splits the prefixes into ssh_from4 and ssh_from6 in Canon's form; nft prints a full-length prefix as its
// address.
func sshSets(ps []netip.Prefix) (v4, v6 []string) {
	for _, p := range ps {
		e := p.String()
		if p.IsSingleIP() {
			e = p.Addr().String()
		}
		if p.Addr().Is4() {
			v4 = append(v4, e)
		} else {
			v6 = append(v6, e)
		}
	}
	return v4, v6
}

// RootdSets are the sets only rootd fills. Exact ones must equal rootd.db; timeout (dst) ones may only hold answers
// rootd recorded and that have not expired, so an empty set passes.
var (
	ExactSets = []string{"port_allow", "allow_private4", "allow_private6"}
	// FixedPortAllow are the port_allow tuples every box has (Appendix B): root may open approvald's 127.0.0.1:43100
	// and ntfy's :43200. rootd records them at start (RecordFixed); app tuples come with the apps.
	FixedPortAllow = []string{"0 . 43100", "0 . 43200"}
	DstSets        = []string{"proxy_dst4", "proxy_dst6", "keys_dst4", "keys_dst6", "git_dst4", "git_dst6", "ntfy_dst4", "ntfy_dst6"}
)

//go:embed agentbox.nft
var ruleset string

// Render returns the ruleset with the static sets, the SSH sources and the reserved ports filled in.
func Render(sshFrom []netip.Prefix) []byte {
	v4, v6 := sshSets(sshFrom)
	elems := func(es []string) string { // an empty elements block is a syntax error
		if len(es) == 0 {
			return ""
		}
		return "elements = { " + strings.Join(es, ", ") + " }"
	}
	return []byte(strings.NewReplacer("{{.Confined}}", strings.Join(Confined, ", "), "{{.Private4}}", strings.Join(Private4, ", "),
		"{{.Private6}}", strings.Join(Private6, ", "), "{{.Reserved}}", fmt.Sprintf("%d-%d", ReservedLo, ReservedHi),
		"{{.SSHFrom4}}", elems(v4), "{{.SSHFrom6}}", elems(v6)).Replace(ruleset))
}

// Table is a parsed `nft -j -s list table inet agentbox`.
type Table struct {
	Hash  string              // sha256 of the normalized stateless JSON, set elements excluded
	Elems map[string][]string // set name -> canonical elements, sorted
}

// ParseTable normalizes nft's JSON: metainfo and every handle go (a reload renumbers rules), set elements are taken out
// into Elems, objects other than rules are sorted by kind and name (a set added by a later release gets a later
// handle), and rules keep their order.
func ParseTable(b []byte) (Table, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var doc struct {
		Nftables []map[string]map[string]any `json:"nftables"`
	}
	if err := d.Decode(&doc); err != nil {
		return Table{}, fmt.Errorf("nft json: %w", err)
	}
	t := Table{Elems: map[string][]string{}}
	type obj struct {
		kind, name string
		v          map[string]map[string]any
	}
	var objs, rules []obj
	for _, o := range doc.Nftables {
		for k, v := range o {
			if k == "metainfo" {
				continue
			}
			delete(v, "handle")
			name, _ := v["name"].(string)
			if k == "set" {
				es := []string{}
				if l, ok := v["elem"].([]any); ok {
					for _, e := range l {
						es = append(es, canonJSON(e))
					}
				}
				sort.Strings(es)
				t.Elems[name] = es
				delete(v, "elem")
			}
			if k == "rule" {
				rules = append(rules, obj{k, name, o})
			} else {
				objs = append(objs, obj{k, name, o})
			}
		}
	}
	if len(objs) == 0 {
		return Table{}, errors.New("nft json: no table")
	}
	sort.SliceStable(objs, func(i, j int) bool {
		return objs[i].kind+"\x00"+objs[i].name < objs[j].kind+"\x00"+objs[j].name
	})
	var all []map[string]map[string]any
	for _, o := range append(objs, rules...) {
		all = append(all, o.v)
	}
	n, err := json.Marshal(all) // map keys come out sorted
	if err != nil {
		return Table{}, err
	}
	h := sha256.Sum256(n)
	t.Hash = hex.EncodeToString(h[:])
	return t, nil
}

// canonJSON turns one nft JSON set element into the text form rootd.db stores: "0 . 43100", "1.2.3.4 . 443",
// "70001-70999", "10.0.0.0/8". Unknown shapes come out as their JSON, so they never match an expected element.
func canonJSON(v any) string {
	switch x := v.(type) {
	case json.Number:
		return x.String()
	case string:
		if a, err := netip.ParseAddr(x); err == nil {
			return a.String()
		}
		return x
	case map[string]any:
		if e, ok := x["elem"].(map[string]any); ok {
			return canonJSON(e["val"])
		}
		if c, ok := x["concat"].([]any); ok {
			p := make([]string, len(c))
			for i, e := range c {
				p[i] = canonJSON(e)
			}
			return strings.Join(p, " . ")
		}
		if r, ok := x["range"].([]any); ok && len(r) == 2 {
			return canonJSON(r[0]) + "-" + canonJSON(r[1])
		}
		if p, ok := x["prefix"].(map[string]any); ok {
			a, err1 := netip.ParseAddr(fmt.Sprint(p["addr"]))
			l, err2 := strconv.Atoi(fmt.Sprint(p["len"]))
			if err1 == nil && err2 == nil {
				if pf, err := a.Prefix(l); err == nil && pf.Addr() == a {
					return pf.String()
				}
			}
		}
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// Canon normalizes an element in rootd.db's text form. Each " . "-separated part must be a number, a number range,
// an address or a prefix: rootd.db's text goes into an nft script, so anything else is refused.
func Canon(s string) (string, error) {
	parts := strings.Split(s, " . ")
	for i, p := range parts {
		switch {
		case isUint(p):
			n, _ := strconv.ParseUint(p, 10, 32)
			parts[i] = strconv.FormatUint(n, 10)
		case strings.Count(p, "-") == 1 && isUint(p[:strings.Index(p, "-")]) && isUint(p[strings.Index(p, "-")+1:]):
		default:
			if pf, err := netip.ParsePrefix(p); err == nil && pf.Masked() == pf {
				parts[i] = pf.String()
			} else if a, err := netip.ParseAddr(p); err == nil && a.Zone() == "" {
				parts[i] = a.String()
			} else {
				return "", fmt.Errorf("bad set element %q", s)
			}
		}
	}
	return strings.Join(parts, " . "), nil
}

func isUint(s string) bool {
	_, err := strconv.ParseUint(s, 10, 32)
	return err == nil && s != "" && s[0] != '+'
}

// Row is one rootd.db set_elements row (Appendix E). Expires is Unix milliseconds UTC; nil means no timeout.
type Row struct {
	Set     string
	Elem    string
	Expires *int64
}

// ReadRows reads set_elements from rootd's open rootd.db (the modernc.org/sqlite driver rootd registers).
func ReadRows(db *sql.DB) ([]Row, error) {
	rs, err := db.Query(`SELECT set_name, element, expires_at FROM set_elements`)
	if err != nil {
		return nil, fmt.Errorf("rootd.db set_elements: %w", err)
	}
	defer rs.Close()
	var rows []Row
	for rs.Next() {
		var r Row
		var exp sql.NullInt64
		if err := rs.Scan(&r.Set, &r.Elem, &exp); err != nil {
			return nil, err
		}
		if exp.Valid {
			r.Expires = &exp.Int64
		}
		rows = append(rows, r)
	}
	return rows, rs.Err()
}

// Clock returns this boot's id and the wall clock minus CLOCK_MONOTONIC, in ms. nft element timeouts run on jiffies,
// which keep the monotonic clock's pace: within one boot, a change in the offset is a wall step (timesyncd, a VM
// resume) that the dst rows' wall-clock expiries must follow (rootd rebases them; fwcheck rebases its now).
func Clock() (string, int64) {
	b, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return strings.TrimSpace(string(b)), time.Now().UnixMilli() - ts.Nano()/1e6
}

// ClockStep is the wall step, in ms, since rootd last recorded the clock in rootd.db (its clock row) in this boot: the
// rows' expiries are on the wall clock as it was then. 0 across a reboot, or before rootd recorded one.
func ClockStep(db *sql.DB, boot string, off int64) (int64, error) {
	var b string
	var o int64
	err := db.QueryRow(`SELECT boot_id, offset_ms FROM clock`).Scan(&b, &o)
	if errors.Is(err, sql.ErrNoRows) || (err != nil && strings.Contains(err.Error(), "no such table")) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("rootd.db clock: %w", err)
	}
	if b != boot {
		return 0, nil
	}
	return off - o, nil
}

// readDB is fwcheck's read-only look at rootd.db. A missing rootd.db or set_elements table means rootd has never run,
// so it has recorded no element. step is ClockStep for boot and off (Clock).
func readDB(path, boot string, off int64) (rows []Row, step int64, err error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, 0, nil
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, 0, err
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='set_elements'`).Scan(&n); err != nil {
		return nil, 0, fmt.Errorf("%s: %w", path, err)
	}
	if n == 0 {
		return nil, 0, nil
	}
	if step, err = ClockStep(db, boot, off); err != nil {
		return nil, 0, err
	}
	rows, err = ReadRows(db)
	return rows, step, err
}

// Static checks the static sets against the constants and the SSH sources (rootd never inserts into them); each problem
// is one line.
func Static(live map[string][]string, sshFrom []netip.Prefix) []string {
	var bad []string
	v4, v6 := sshSets(sshFrom)
	for s, w := range map[string][]string{"confined": Confined, "private4": Private4, "private6": Private6, "ssh_from4": v4, "ssh_from6": v6} {
		bad = append(bad, diff(s, live[s], w)...)
	}
	sort.Strings(bad)
	return bad
}

func diff(set string, live, want []string) []string {
	var bad []string
	exp := map[string]bool{}
	for _, e := range want {
		if c, err := Canon(e); err == nil {
			e = c
		}
		exp[e] = true
	}
	got := map[string]bool{}
	for _, e := range live {
		got[e] = true
		if !exp[e] {
			bad = append(bad, fmt.Sprintf("set %s: unexpected element %s", set, e))
		}
	}
	for e := range exp {
		if !got[e] {
			bad = append(bad, fmt.Sprintf("set %s: missing element %s", set, e))
		}
	}
	return bad
}

// Compare checks rootd's sets against its set_elements rows; each problem is one line.
func Compare(live map[string][]string, rows []Row, now time.Time) []string {
	var bad []string
	want := map[string][]string{}
	for _, s := range ExactSets {
		want[s] = []string{}
	}
	ok := map[string]map[string]bool{} // dst set -> answers rootd recorded that have not expired
	for _, s := range DstSets {
		ok[s] = map[string]bool{}
	}
	for _, r := range rows {
		e, err := Canon(r.Elem)
		switch {
		case err != nil:
			bad = append(bad, fmt.Sprintf("rootd.db set %s: %v", r.Set, err))
		case slices.Contains(ExactSets, r.Set):
			want[r.Set] = append(want[r.Set], e)
		case ok[r.Set] != nil:
			// an element nft still holds can outlive its row's expiry by a moment
			if r.Expires == nil || *r.Expires > now.UnixMilli()-ElementSlack.Milliseconds() {
				ok[r.Set][e] = true
			}
		default:
			bad = append(bad, fmt.Sprintf("rootd.db names set %q, which rootd may not fill", r.Set))
		}
	}
	for s, w := range want {
		bad = append(bad, diff(s, live[s], w)...)
	}
	for s, a := range ok {
		for _, e := range live[s] {
			if !a[e] {
				bad = append(bad, fmt.Sprintf("set %s: element %s is not an unexpired rootd answer", s, e))
			}
		}
	}
	sort.Strings(bad)
	return bad
}

// ReservedOK reports whether ip_local_reserved_ports ("a-b,c,...") covers the reserved range.
func ReservedOK(v string) bool {
	for _, r := range strings.Split(strings.TrimSpace(v), ",") {
		lo, hi, _ := strings.Cut(r, "-")
		if hi == "" {
			hi = lo
		}
		a, err1 := strconv.Atoi(lo)
		b, err2 := strconv.Atoi(hi)
		if err1 == nil && err2 == nil && a <= ReservedLo && b >= ReservedHi {
			return true
		}
	}
	return false
}

func cmdErr(err error) error {
	var ee *exec.ExitError
	if errors.As(err, &ee) && len(ee.Stderr) > 0 {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(ee.Stderr)))
	}
	return err
}

func live() (Table, error) {
	out, err := exec.Command("nft", "-j", "-s", "list", "table", "inet", "agentbox").Output()
	if err != nil {
		return Table{}, fmt.Errorf("nft list table inet agentbox: %w", cmdErr(err))
	}
	return ParseTable(out)
}

// expected loads the ruleset into a fresh network namespace and lists it there: the hash every box with this release
// must have, whatever was in the live table before the add-only load.
func expected(sshFrom []netip.Prefix) (Table, error) {
	c := exec.Command("unshare", "--net", "sh", "-c", "nft -f - && nft -j -s list table inet agentbox")
	c.Stdin = bytes.NewReader(Render(sshFrom))
	out, err := c.Output()
	if err != nil {
		return Table{}, fmt.Errorf("ruleset in a scratch netns: %w", cmdErr(err))
	}
	return ParseTable(out)
}

// verifyTable compares the live table's hash to the ruleset's and its static sets to the constants. rootd's sets are
// left to Check.
func verifyTable() (Table, []string, error) {
	ssh, err := SSHFrom()
	if err != nil {
		return Table{}, nil, err
	}
	want, err := expected(ssh)
	if err != nil {
		return Table{}, nil, err
	}
	got, err := live()
	if err != nil {
		return Table{}, []string{err.Error()}, nil
	}
	var bad []string
	if got.Hash != want.Hash {
		bad = append(bad, fmt.Sprintf("table inet agentbox: stateless hash %s, the ruleset gives %s (rules, chains or set definitions changed)", got.Hash, want.Hash))
	}
	return got, append(bad, Static(got.Elems, ssh)...), nil
}

func writeFile(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, b) {
		return nil
	}
	tmp := path + ".new"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// WriteConfig writes the rendered ruleset and the reserved-ports sysctl file, then checks the ruleset with nft -c.
func WriteConfig() error {
	ssh, err := SSHFrom()
	if err != nil {
		return err
	}
	if err := writeFile(RulesPath, Render(ssh)); err != nil {
		return err
	}
	if err := writeFile(SysctlPath, []byte(fmt.Sprintf("# agentbox (ARCHITECTURE.md §6.1): no ephemeral port in the reserved loopback service range\nnet.ipv4.ip_local_reserved_ports = %d-%d\n", ReservedLo, ReservedHi))); err != nil {
		return err
	}
	if out, err := exec.Command("nft", "-c", "-f", RulesPath).CombinedOutput(); err != nil {
		return fmt.Errorf("nft -c -f %s: %v: %s", RulesPath, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Load is agentbox-firewall.service: config, the reserved ports, one nft -f, then the table check.
func Load() error {
	if err := WriteConfig(); err != nil {
		return err
	}
	cur, err := os.ReadFile(reservedSysctl)
	if err != nil {
		return err
	}
	if !ReservedOK(string(cur)) {
		v := fmt.Sprintf("%d-%d", ReservedLo, ReservedHi)
		if s := strings.TrimSpace(string(cur)); s != "" {
			v = s + "," + v
		}
		if err := os.WriteFile(reservedSysctl, []byte(v), 0o644); err != nil {
			return err
		}
	}
	if out, err := exec.Command("nft", "-f", RulesPath).CombinedOutput(); err != nil {
		return fmt.Errorf("nft -f %s: %v: %s", RulesPath, err, strings.TrimSpace(string(out)))
	}
	_, bad, err := verifyTable()
	if err == nil && len(bad) > 0 {
		err = errors.New(strings.Join(bad, "; "))
	}
	return err
}

// Check is fwcheck; it returns every problem found, or an error if it could not look.
func Check(db string, now time.Time) ([]string, error) {
	t, bad, err := verifyTable()
	if err != nil {
		return nil, err
	}
	if t.Elems != nil {
		boot, off := Clock()
		rows, step, err := readDB(db, boot, off)
		if err != nil {
			return nil, err
		}
		// a wall step since rootd's last write moved now, not the kernel's timeouts: compare on the rows' clock
		bad = append(bad, Compare(t.Elems, rows, now.Add(-time.Duration(step)*time.Millisecond))...)
	}
	if b, err := os.ReadFile(reservedSysctl); err != nil || !ReservedOK(string(b)) {
		bad = append(bad, fmt.Sprintf("%s is %q, not covering %d-%d", reservedSysctl, strings.TrimSpace(string(b)), ReservedLo, ReservedHi))
	}
	if s, _ := exec.Command("systemctl", "is-enabled", "nftables.service").Output(); strings.TrimSpace(string(s)) != "masked" {
		bad = append(bad, fmt.Sprintf("nftables.service is %q, not masked (its config and ExecStop flush the whole ruleset)", strings.TrimSpace(string(s))))
	}
	return bad, nil
}

// RefillScript returns the nft commands that make the exact sets match rootd's rows: add what is missing, delete what
// rootd never recorded. Elements already there are left alone. Dst rows are checked but left to rootd's resolver,
// which also revokes by entry and cuts conntrack.
func RefillScript(live map[string][]string, rows []Row) (string, error) {
	sets := map[string]map[string]bool{}
	for _, s := range ExactSets {
		sets[s] = map[string]bool{}
	}
	for _, r := range rows {
		e, err := Canon(r.Elem)
		if err != nil {
			return "", err
		}
		if slices.Contains(DstSets, r.Set) {
			continue
		}
		m := sets[r.Set]
		if m == nil {
			return "", fmt.Errorf("rootd.db names set %q, which rootd may not fill", r.Set)
		}
		m[e] = true
	}
	var b strings.Builder
	for _, s := range ExactSets {
		have := map[string]bool{}
		for _, e := range live[s] {
			have[e] = true
			if !sets[s][e] {
				fmt.Fprintf(&b, "delete element inet agentbox %s { %s }\n", s, e)
			}
		}
		var add []string
		for e := range sets[s] {
			if !have[e] {
				add = append(add, e)
			}
		}
		sort.Strings(add)
		for _, e := range add {
			fmt.Fprintf(&b, "add element inet agentbox %s { %s }\n", s, e)
		}
	}
	return b.String(), nil
}

// RecordFixed writes the FixedPortAllow rows to rootd.db's set_elements; rootd runs it at start, before its refill.
func RecordFixed(db *sql.DB) error {
	for _, e := range FixedPortAllow {
		if _, err := db.Exec(`INSERT OR IGNORE INTO set_elements VALUES ('port_allow', ?, NULL)`, e); err != nil {
			return err
		}
	}
	return nil
}

// Refill runs RefillScript on rootd's open rootd.db as one nft transaction.
func Refill(db *sql.DB) error {
	rows, err := ReadRows(db)
	if err != nil {
		return err
	}
	t, err := live()
	if err != nil {
		return err
	}
	s, err := RefillScript(t.Elems, rows)
	if err != nil || s == "" {
		return err
	}
	c := exec.Command("nft", "-f", "-")
	c.Stdin = strings.NewReader(s)
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("nft refill: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
