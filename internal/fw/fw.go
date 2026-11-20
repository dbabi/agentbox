// Package fw loads and verifies the inet agentbox nftables table (ARCHITECTURE.md §6.1, Appendix B).
//
// Load is agentbox-firewall.service: one add-only nft -f transaction, then a check that the live table is the one the
// ruleset makes. Check is fwcheck: the normalized stateless hash, the static sets, the sets rootd fills (compared to
// rootd.db's set_elements rows, Appendix E), the reserved loopback ports, ntfy's uid and the masked nftables.service.
// Refill makes rootd's sets match rootd.db; rootd runs it at start, before READY=1.
package fw

import (
	"bytes"
	"crypto/sha256"
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
)

const (
	RulesPath  = "/etc/nftables.d/agentbox.nft"
	SysctlPath = "/etc/sysctl.d/60-agentbox.conf"
	RootdDB    = "/var/lib/agentbox/rootd.db"
	// Reserved loopback service ports (§6.1): only (uid . port) tuples in port_allow may open them.
	ReservedLo, ReservedHi = 43000, 45999
	ElementTimeout         = 10 * time.Minute
	reservedSysctl         = "/proc/sys/net/ipv4/ip_local_reserved_ports"
)

// The static sets. rootd never inserts into them; rootd's address checks (Appendix B) use Private4 and Private6 too,
// so the Go table and the nft sets come from this one list.
var (
	// every agent (70001-70999) and app (71001-71999) uid and the whole sub-id span 0x70000000-0x77FFFFFF (§4.1)
	Confined = []string{"70001-70999", "71001-71999", "1879048192-2013265919"}
	Private4 = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3"}
	Private6 = []string{"::/127", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64", "2001:db8::/32", "fc00::/7",
		"fe80::/10", "fec0::/10", "ff00::/8"}
)

// RootdSets are the sets only rootd fills. Exact ones must equal rootd.db; timeout (dst) ones may only hold answers
// rootd recorded and that have not expired, so an empty set passes.
var (
	ExactSets = []string{"port_allow", "allow_private4", "allow_private6"}
	DstSets   = []string{"proxy_dst4", "proxy_dst6", "keys_dst4", "keys_dst6", "git_dst4", "git_dst6", "ntfy_dst4", "ntfy_dst6"}
)

//go:embed agentbox.nft
var ruleset string

// Render returns the ruleset with the static sets and the reserved ports filled in.
func Render() []byte {
	return []byte(strings.NewReplacer("{{.Confined}}", strings.Join(Confined, ", "), "{{.Private4}}", strings.Join(Private4, ", "),
		"{{.Private6}}", strings.Join(Private6, ", "), "{{.Reserved}}", fmt.Sprintf("%d-%d", ReservedLo, ReservedHi)).Replace(ruleset))
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

// Row is one rootd.db set_elements row (Appendix E). Expires is unix seconds; nil means no timeout.
type Row struct {
	Set     string `json:"set_name"`
	Elem    string `json:"element"`
	Expires *int64 `json:"expires_at"`
}

// ReadRows reads set_elements read-only. A missing rootd.db means rootd has never run, so it has recorded no element.
// shortcut: the sqlite3 CLI instead of a Go SQLite driver (stdlib only, no module proxy here); switch to rootd's
// driver once rootd.db code lands.
func ReadRows(db string) ([]Row, error) {
	if _, err := os.Stat(db); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	out, err := exec.Command("sqlite3", "-readonly", "-json", "-cmd", ".timeout 5000", db,
		"SELECT set_name, element, expires_at FROM set_elements").Output()
	if err != nil {
		return nil, fmt.Errorf("read %s set_elements: %w", db, cmdErr(err))
	}
	var rows []Row
	if len(bytes.TrimSpace(out)) == 0 {
		return nil, nil // sqlite3 prints nothing for no rows
	}
	if err := json.Unmarshal(out, &rows); err != nil {
		return nil, fmt.Errorf("read %s set_elements: %w", db, err)
	}
	return rows, nil
}

// Static checks the static sets against the constants (rootd never inserts into them); each problem is one line.
func Static(live map[string][]string) []string {
	var bad []string
	for s, w := range map[string][]string{"confined": Confined, "private4": Private4, "private6": Private6} {
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
			// 5 s of slack: an element nft still holds can outlive its row's second by a moment
			if r.Expires == nil || *r.Expires > now.Unix()-5 {
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
func expected() (Table, error) {
	c := exec.Command("unshare", "--net", "sh", "-c", "nft -f - && nft -j -s list table inet agentbox")
	c.Stdin = bytes.NewReader(Render())
	out, err := c.Output()
	if err != nil {
		return Table{}, fmt.Errorf("ruleset in a scratch netns: %w", cmdErr(err))
	}
	return ParseTable(out)
}

// verifyTable compares the live table's hash to the ruleset's and its static sets to the constants. rootd's sets are
// left to Check.
func verifyTable() (Table, []string, error) {
	want, err := expected()
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
	return got, append(bad, Static(got.Elems)...), nil
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
	if err := writeFile(RulesPath, Render()); err != nil {
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
		rows, err := ReadRows(db)
		if err != nil {
			return nil, err
		}
		bad = append(bad, Compare(t.Elems, rows, now)...)
	}
	if b, err := os.ReadFile(reservedSysctl); err != nil || !ReservedOK(string(b)) {
		bad = append(bad, fmt.Sprintf("%s is %q, not covering %d-%d", reservedSysctl, strings.TrimSpace(string(b)), ReservedLo, ReservedHi))
	}
	if u, _ := exec.Command("systemctl", "show", "-p", "User", "--value", "ntfy.service").Output(); strings.TrimSpace(string(u)) != "_ntfy" {
		bad = append(bad, fmt.Sprintf("ntfy.service runs as %q, not _ntfy, the uid the ruleset names", strings.TrimSpace(string(u))))
	}
	if s, _ := exec.Command("systemctl", "is-enabled", "nftables.service").Output(); strings.TrimSpace(string(s)) != "masked" {
		bad = append(bad, fmt.Sprintf("nftables.service is %q, not masked (its config and ExecStop flush the whole ruleset)", strings.TrimSpace(string(s))))
	}
	return bad, nil
}

// RefillScript returns the nft commands that make rootd's sets match its rows: add what is missing (a dst answer with
// its remaining timeout), delete what rootd never recorded or has expired. Elements already there are left alone, so
// their expiry keeps running.
func RefillScript(live map[string][]string, rows []Row, now time.Time) (string, error) {
	type want struct{ left time.Duration } // 0: no timeout
	sets := map[string]map[string]want{}
	for _, s := range append(slices.Clone(ExactSets), DstSets...) {
		sets[s] = map[string]want{}
	}
	for _, r := range rows {
		e, err := Canon(r.Elem)
		if err != nil {
			return "", err
		}
		m := sets[r.Set]
		if m == nil {
			return "", fmt.Errorf("rootd.db names set %q, which rootd may not fill", r.Set)
		}
		var w want
		if r.Expires != nil && slices.Contains(DstSets, r.Set) {
			if w.left = time.Unix(*r.Expires, 0).Sub(now).Truncate(time.Second); w.left <= 0 {
				continue
			}
		}
		m[e] = w
	}
	var b strings.Builder
	names := append(slices.Clone(ExactSets), DstSets...)
	for _, s := range names {
		have := map[string]bool{}
		for _, e := range live[s] {
			have[e] = true
			if _, ok := sets[s][e]; !ok {
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
			if w := sets[s][e]; w.left > 0 {
				fmt.Fprintf(&b, "add element inet agentbox %s { %s timeout %ds expires %ds }\n", s, e, int64(max(w.left, ElementTimeout)/time.Second), int64(w.left/time.Second))
			} else {
				fmt.Fprintf(&b, "add element inet agentbox %s { %s }\n", s, e)
			}
		}
	}
	return b.String(), nil
}

// Refill runs RefillScript as one nft transaction.
func Refill(db string, now time.Time) error {
	rows, err := ReadRows(db)
	if err != nil {
		return err
	}
	t, err := live()
	if err != nil {
		return err
	}
	s, err := RefillScript(t.Elems, rows, now)
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
