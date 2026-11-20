package resolve

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"agentbox/internal/fw"
	"agentbox/internal/rootd/nl"
)

// Schema is the resolver's part of rootd.db (Appendix E). set_elements is the refill source and what fwcheck reads:
// every element any dst set may hold, with the latest expiry. set_answers says which entry each element answers, so a
// removed entry revokes exactly its elements; an element two entries share stays until both are gone.
const Schema = `
CREATE TABLE IF NOT EXISTS set_elements(set_name TEXT NOT NULL, element TEXT NOT NULL, expires_at INTEGER,
  PRIMARY KEY(set_name, element)) STRICT;
CREATE TABLE IF NOT EXISTS set_answers(entry TEXT NOT NULL, set_name TEXT NOT NULL, element TEXT NOT NULL,
  expires_at INTEGER NOT NULL, PRIMARY KEY(entry, set_name, element)) STRICT;
`

// Sets are the destination sets rootd owns.
var Sets = fw.DstSets

// Service is rootd's resolver. Every field but Deny and TaskAgent is required.
type Service struct {
	DB       *sql.DB
	Dir      string // EgressDir
	Resolver interface {
		ResolveHostname(context.Context, string) ([]netip.Addr, error)
	}
	Route func(netip.Addr) string // nl.CheckRoute
	Nft   interface {
		Run(string) error
		List(string) ([]string, error)
	}
	Flows   func(netip.Addr, uint16) (int, error) // nl.DeleteFlows
	Now     func() time.Time
	Timeout time.Duration // set element timeout: 10 min (Appendix B)
	// Deny receives each refusal; detail (addresses, the failed check) is for audit only.
	Deny func(svc, entry, reason, detail string)
	// TaskAgent maps a live task to its agent, for the proxy's per-agent list. Until the task registry lands
	// (weeks 4-6) it is nil, and the proxy resolves nothing.
	TaskAgent func(task string) (string, bool)

	mu sync.Mutex
}

func entryKey(svc string, e Entry) string { return svc + " " + e.String() }

func parseEntryKey(k string) (string, Entry, error) {
	svc, rest, _ := strings.Cut(k, " ")
	e, err := ParseEntry(rest)
	return svc, e, err
}

func (s *Service) deny(svc string, e Entry, reason, detail string) *Refused {
	if s.Deny != nil {
		s.Deny(svc, e.String(), reason, detail)
	}
	return &Refused{reason, detail}
}

// Resolve is one broker request: re-check the allowlist, resolve, refuse the whole name if any answer fails a check,
// record the answers in rootd.db, then add them to <svc>_dst with the element timeout. It returns the addresses in
// resolved's order and their expiry.
func (s *Service) Resolve(ctx context.Context, svc, task string, e Entry) ([]netip.Addr, time.Time, error) {
	agent := ""
	if svc == "proxy" {
		ok := false
		if s.TaskAgent != nil {
			agent, ok = s.TaskAgent(task)
		}
		if !ok {
			return nil, time.Time{}, s.deny(svc, e, NotAllowlisted, "no live task "+task)
		}
	}
	allowed := func() (bool, error) {
		l, err := LoadLists(s.Dir)
		if err != nil {
			return false, err
		}
		return l.Allowed(svc, agent, e), nil
	}
	if ok, err := allowed(); err != nil {
		return nil, time.Time{}, s.deny(svc, e, Unavailable, err.Error())
	} else if !ok {
		return nil, time.Time{}, s.deny(svc, e, NotAllowlisted, "")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	addrs, err := s.Resolver.ResolveHostname(ctx, e.Host)
	if err != nil {
		r, ok := err.(*Refused)
		if !ok {
			r = &Refused{Unavailable, err.Error()}
		}
		return nil, time.Time{}, s.deny(svc, e, r.Reason, r.Detail)
	}
	var use []netip.Addr
	for _, a := range addrs {
		why := CheckPrefix(a)
		if why == "" {
			why = s.Route(a)
		}
		switch why {
		case "":
			use = append(use, a)
		case nl.NoDefaultRoute:
			// the box has no route for this family (IPv4-only LAN): unusable, not a reason to refuse the name
		default:
			return nil, time.Time{}, s.deny(svc, e, NonPublic, fmt.Sprintf("%s: %s (answers %v)", a, why, addrs))
		}
	}
	if len(use) == 0 {
		return nil, time.Time{}, s.deny(svc, e, Unavailable, fmt.Sprintf("no default route for any answer %v", addrs))
	}
	addrs = use

	s.mu.Lock()
	defer s.mu.Unlock()
	if ok, err := allowed(); err != nil || !ok { // removed while we resolved: the removal's revocation already ran
		return nil, time.Time{}, s.deny(svc, e, NotAllowlisted, "removed during resolution")
	}
	now := s.Now()
	exp := now.Add(s.Timeout)
	var add []Timed
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, time.Time{}, s.deny(svc, e, Unavailable, err.Error())
	}
	defer tx.Rollback()
	for _, a := range addrs {
		el := Elem{SetFor(svc, a), a, e.Port}
		if _, err := tx.Exec(`INSERT INTO set_answers VALUES(?,?,?,?) ON CONFLICT DO UPDATE SET expires_at=excluded.expires_at`,
			entryKey(svc, e), el.Set, el.Key(), exp.UnixMilli()); err != nil {
			return nil, time.Time{}, s.deny(svc, e, Unavailable, err.Error())
		}
		add = append(add, Timed{el, s.Timeout})
	}
	// the row before the element (§6.1): fwcheck and refill trust rootd.db, never the kernel
	if err := syncElements(tx, now.UnixMilli()); err != nil {
		return nil, time.Time{}, s.deny(svc, e, Unavailable, err.Error())
	}
	if err := tx.Commit(); err != nil {
		return nil, time.Time{}, s.deny(svc, e, Unavailable, err.Error())
	}
	if err := s.Nft.Run(AddScript(add, s.Timeout)); err != nil {
		return nil, time.Time{}, s.deny(svc, e, Unavailable, err.Error())
	}
	return addrs, exp, nil
}

// syncElements recomputes set_elements from the unexpired set_answers: one row per element, the latest expiry.
func syncElements(tx *sql.Tx, now int64) error {
	q := `DELETE FROM set_elements WHERE set_name IN (` + strings.Repeat("?,", len(Sets)-1) + `?)`
	args := make([]any, len(Sets))
	for i, v := range Sets {
		args[i] = v
	}
	if _, err := tx.Exec(q, args...); err != nil {
		return err
	}
	_, err := tx.Exec(`INSERT INTO set_elements SELECT set_name, element, MAX(expires_at) FROM set_answers
		WHERE expires_at > ? GROUP BY set_name, element`, now)
	return err
}

func elements(tx *sql.Tx) (map[string]int64, error) {
	rows, err := tx.Query(`SELECT set_name, element, expires_at FROM set_elements`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]int64{}
	for rows.Next() {
		var set, el string
		var exp int64
		if err := rows.Scan(&set, &el, &exp); err != nil {
			return nil, err
		}
		if slices.Contains(Sets, set) {
			m[set+"\x00"+el] = exp
		}
	}
	return m, rows.Err()
}

func splitKey(k string) (Elem, error) {
	set, el, _ := strings.Cut(k, "\x00")
	return ParseElem(set, el)
}

// RefillResult says what a refill changed.
type RefillResult struct {
	Revoked, Expired, Added, Extra, Flows int
}

// AnswerRetention is how long an expired answer is kept: its element is gone, but a flow that began while it was live
// survives expiry (Appendix B), and removing the entry must still find and cut that flow.
const AnswerRetention = 7 * 24 * time.Hour

func answerElems(tx *sql.Tx, where string, args ...any) (map[string]bool, error) {
	rows, err := tx.Query(`SELECT set_name, element FROM set_answers `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]bool{}
	for rows.Next() {
		var set, el string
		if err := rows.Scan(&set, &el); err != nil {
			return nil, err
		}
		m[set+"\x00"+el] = true
	}
	return m, rows.Err()
}

// Refill makes the dst sets match rootd.db and the allowlists. An entry that no list names any more is revoked: its
// elements leave the sets and their conntrack entries are deleted, which cuts established flows at once, even flows
// whose element already expired. Expired answers stay AnswerRetention for that, but leave set_elements (the kernel
// already dropped them; established flows survive expiry). Every live element is re-added with its remaining expiry,
// and any element the kernel holds that rootd.db does not is removed. rootd runs it before READY=1, on its timer and
// on an admin notify.
func (s *Service) Refill() (RefillResult, error) {
	var res RefillResult
	l, err := LoadLists(s.Dir)
	if err != nil {
		return res, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.Now().UnixMilli()
	tx, err := s.DB.Begin()
	if err != nil {
		return res, err
	}
	defer tx.Rollback()
	before, err := elements(tx)
	if err != nil {
		return res, err
	}
	rows, err := tx.Query(`SELECT DISTINCT entry FROM set_answers`)
	if err != nil {
		return res, err
	}
	var revoked []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			rows.Close()
			return res, err
		}
		svc, e, err := parseEntryKey(k)
		if err != nil || !l.AllowedAny(svc, e) {
			revoked = append(revoked, k)
		}
	}
	rows.Close()
	cutKeys := map[string]bool{}
	for _, k := range revoked {
		m, err := answerElems(tx, `WHERE entry=?`, k)
		if err != nil {
			return res, err
		}
		for el := range m {
			cutKeys[el] = true
		}
		if _, err := tx.Exec(`DELETE FROM set_answers WHERE entry=?`, k); err != nil {
			return res, err
		}
	}
	kept, err := answerElems(tx, ``) // a still-listed entry answers the same addr . port: it stays reachable
	if err != nil {
		return res, err
	}
	if _, err := tx.Exec(`DELETE FROM set_answers WHERE expires_at <= ?`, now-AnswerRetention.Milliseconds()); err != nil {
		return res, err
	}
	if err := syncElements(tx, now); err != nil {
		return res, err
	}
	live, err := elements(tx)
	if err != nil {
		return res, err
	}
	if err := tx.Commit(); err != nil {
		return res, err
	}

	var cut, gone []Elem
	for k := range cutKeys {
		if kept[k] {
			continue
		}
		el, err := splitKey(k)
		if err != nil {
			return res, err
		}
		cut = append(cut, el)
	}
	for k := range before {
		if _, ok := live[k]; !ok && !cutKeys[k] {
			el, err := splitKey(k)
			if err != nil {
				return res, err
			}
			gone = append(gone, el)
		}
	}
	res.Revoked, res.Expired = len(cut), len(gone)
	var add []Timed
	for k, exp := range live {
		el, err := splitKey(k)
		if err != nil {
			return res, err
		}
		if left := time.Duration(exp-now) * time.Millisecond; left >= time.Second { // shorter: gone before nft runs
			add = append(add, Timed{el, left})
		}
	}
	// elements the kernel holds that rootd.db doesn't: rootd never added them, so they go too
	for _, set := range Sets {
		keys, err := s.Nft.List(set)
		if err != nil {
			return res, err
		}
		for _, k := range keys {
			if _, ok := live[set+"\x00"+k]; !ok {
				el, err := ParseElem(set, k)
				if err != nil {
					return res, err
				}
				if !slices.Contains(cut, el) && !slices.Contains(gone, el) {
					res.Extra++
					gone = append(gone, el)
				}
			}
		}
	}
	res.Added = len(add)
	if err := s.Nft.Run(DestroyScript(append(cut, gone...)) + AddScript(add, s.Timeout)); err != nil {
		return res, err
	}
	for _, el := range cut {
		n, err := s.Flows(el.Addr, el.Port)
		res.Flows += n
		if err != nil {
			return res, fmt.Errorf("conntrack delete %s: %v", el.Key(), err)
		}
	}
	return res, nil
}

// Entries lists the elements rootd.db holds for set (fwcheck's expected state).
func (s *Service) Entries() (map[string][]string, error) {
	rows, err := s.DB.Query(`SELECT entry, set_name, element, expires_at FROM set_answers ORDER BY entry, set_name, element`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string][]string{}
	for rows.Next() {
		var k, set, el string
		var exp int64
		if err := rows.Scan(&k, &set, &el, &exp); err != nil {
			return nil, err
		}
		m[k] = append(m[k], fmt.Sprintf("%s %s expires_at=%d", set, el, exp))
	}
	return m, rows.Err()
}
