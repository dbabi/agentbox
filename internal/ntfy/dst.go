package ntfy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"agentbox/internal/rootd/gens"
	"agentbox/internal/rootd/resolve"
)

// The iOS push upstream (§6.1): rootd resolves it, checks every answer and fills ntfy_dst4/ntfy_dst6, the only
// non-DNS destinations nft lets _ntfy reach.
const (
	UpstreamHost = "ntfy.sh"
	UpstreamPort = 443
	// AnswersPath records every answer before its element is added. shortcut: a JSON file stands in for rootd.db's
	// resolution rows until the rootd skeleton lands; fwcheck reads it the same way.
	AnswersPath = "/var/lib/agentbox/resolve/ntfy_dst.json"
	elemTimeout = 10 * time.Minute
)

type Answer struct {
	Addr netip.Addr `json:"addr"`
	Port int        `json:"port"`
	At   int64      `json:"at"` // unix seconds of the last add
}

func setFor(a netip.Addr) string {
	if a.Is4() {
		return "ntfy_dst4"
	}
	return "ntfy_dst6"
}

func readAnswers() ([]Answer, error) {
	b, err := os.ReadFile(AnswersPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var as []Answer
	if err := json.Unmarshal(b, &as); err != nil {
		return nil, fmt.Errorf("%s: %v", AnswersPath, err)
	}
	return as, nil
}

// merge drops answers older than the element timeout and stamps addrs with now.
func merge(old []Answer, addrs []netip.Addr, now time.Time) []Answer {
	var out []Answer
	for _, a := range old {
		if now.Unix()-a.At < int64(elemTimeout/time.Second) && !slices.Contains(addrs, a.Addr) {
			out = append(out, a)
		}
	}
	for _, a := range addrs {
		out = append(out, Answer{a, UpstreamPort, now.Unix()})
	}
	return out
}

// RefreshDst is rootd's 5-minute ntfy_dst refresh. Any answer that fails a check refuses the whole name; each
// answer's record is written before its element is added, and every add resets the element's 10-minute expiry.
func RefreshDst(now time.Time) error {
	addrs, err := resolve.Hostname(UpstreamHost)
	if err != nil {
		return err
	}
	var ok []netip.Addr
	for _, a := range addrs {
		err := resolve.Check(a)
		// an IPv4-only LAN still gets ntfy.sh's AAAA answers: they can't be reached, so they are left out, not refused
		if errors.Is(err, resolve.ErrNoDefaultRoute) {
			continue
		}
		if err != nil {
			return fmt.Errorf("ntfy_dst: refusing %s: %v", UpstreamHost, err)
		}
		ok = append(ok, a)
	}
	if len(ok) == 0 {
		return fmt.Errorf("ntfy_dst: no default route for any %s answer", UpstreamHost)
	}
	addrs = ok
	old, err := readAnswers()
	if err != nil {
		return err
	}
	b, _ := json.Marshal(merge(old, addrs, now))
	if err := os.MkdirAll(filepath.Dir(AnswersPath), 0o700); err != nil {
		return err
	}
	if err := gens.WriteAtomic(AnswersPath, b, 0o600); err != nil {
		return err
	}
	for _, a := range addrs {
		e := fmt.Sprintf("{ %s . %d timeout 10m expires 10m }", a, UpstreamPort)
		if _, err := run("nft", "add", "element", "inet", "agentbox", setFor(a), e); err != nil {
			return err
		}
	}
	return nil
}

type elem struct {
	addr netip.Addr
	port int
}

// parseSetElems reads the elements of `nft -j list set` for an "addr . port" set. Elements with a timeout come
// wrapped as {"elem": {"val": ...}}.
func parseSetElems(b []byte) ([]elem, error) {
	var doc struct {
		Nftables []struct {
			Set *struct {
				Elem []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	var out []elem
	for _, o := range doc.Nftables {
		if o.Set == nil {
			continue
		}
		for _, raw := range o.Set.Elem {
			var e struct {
				Elem *struct {
					Val json.RawMessage `json:"val"`
				} `json:"elem"`
			}
			json.Unmarshal(raw, &e)
			if e.Elem != nil {
				raw = e.Elem.Val
			}
			var c struct {
				Concat []json.RawMessage `json:"concat"`
			}
			if err := json.Unmarshal(raw, &c); err != nil || len(c.Concat) != 2 {
				return nil, fmt.Errorf("unexpected set element %s", raw)
			}
			var s string
			var p int
			if json.Unmarshal(c.Concat[0], &s) != nil || json.Unmarshal(c.Concat[1], &p) != nil {
				return nil, fmt.Errorf("unexpected set element %s", raw)
			}
			a, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("unexpected set element %s", raw)
			}
			out = append(out, elem{a, p})
		}
	}
	return out, nil
}

// checkElems: every element is an answer rootd added within the element timeout. An empty set passes.
func checkElems(set string, es []elem, as []Answer, now time.Time) error {
	for _, e := range es {
		if !slices.ContainsFunc(as, func(a Answer) bool {
			return a.Addr == e.addr && a.Port == e.port && now.Unix()-a.At <= int64(elemTimeout/time.Second)
		}) {
			return fmt.Errorf("fwcheck: %s holds %s . %d, which rootd did not add in the last %v", set, e.addr, e.port, elemTimeout)
		}
	}
	return nil
}

// CheckDst is fwcheck's ntfy_dst assertion (§6.1): each set is a subset of rootd's recent answers. A missing table
// is the firewall check's failure, not this one's.
func CheckDst(now time.Time) error {
	as, err := readAnswers()
	if err != nil {
		return err
	}
	for _, set := range []string{"ntfy_dst4", "ntfy_dst6"} {
		out, err := run("nft", "-j", "list", "set", "inet", "agentbox", set)
		if err != nil {
			if strings.Contains(err.Error(), "No such file or directory") {
				continue
			}
			return err
		}
		es, err := parseSetElems(out)
		if err != nil {
			return fmt.Errorf("fwcheck: %s: %v", set, err)
		}
		if err := checkElems(set, es, as, now); err != nil {
			return err
		}
	}
	return nil
}
