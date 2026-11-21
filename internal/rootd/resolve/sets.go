package resolve

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Table is the nft table agentbox-firewall.service loads (Appendix B); rootd only adds and removes elements of its sets.
const Table = "inet agentbox"

// Elem is one destination-set element: <svc>_dst4 or <svc>_dst6, addr . port.
type Elem struct {
	Set  string
	Addr netip.Addr
	Port uint16
}

// SetFor names the destination set of svc (proxy, keys, git, ntfy) for a's family.
func SetFor(svc string, a netip.Addr) string {
	if a.Is4() {
		return svc + "_dst4"
	}
	return svc + "_dst6"
}

// Key is the element as rootd.db's set_elements.element stores it, and as nft prints it: "<addr> . <port>".
func (e Elem) Key() string { return e.Addr.String() + " . " + strconv.Itoa(int(e.Port)) }

// ParseElem reads a set_elements row back.
func ParseElem(set, key string) (Elem, error) {
	a, p, ok := strings.Cut(key, " . ")
	addr, err := netip.ParseAddr(a)
	port, perr := strconv.ParseUint(p, 10, 16)
	if !ok || err != nil || perr != nil || addr.Zone() != "" || (strings.HasSuffix(set, "4") != addr.Is4()) {
		return Elem{}, fmt.Errorf("bad element %q in %s", key, set)
	}
	return Elem{set, addr, uint16(port)}, nil
}

// Timed is an element with the time it has left.
type Timed struct {
	Elem
	Left time.Duration
}

func ms(d time.Duration) string { return strconv.FormatInt(d.Milliseconds(), 10) + "ms" }

// AddScript adds each element with the fixed timeout and its remaining expiry. No NLM_F_EXCL (add, not create): an
// existing element just takes the new expiry. The kernel refuses an expiry past the timeout (ERANGE), so an element
// recorded under a longer timeout (rootd restarted with a shorter one) keeps its remaining time as its timeout.
func AddScript(es []Timed, timeout time.Duration) string {
	var b strings.Builder
	for _, e := range es {
		fmt.Fprintf(&b, "add element %s %s { %s timeout %s expires %s }\n", Table, e.Set, e.Key(), ms(max(timeout, e.Left)), ms(e.Left))
	}
	return b.String()
}

// DestroyScript removes each element; destroy (nft 1.0.8+) succeeds when it is already gone, e.g. expired.
func DestroyScript(es []Elem) string {
	var b strings.Builder
	for _, e := range es {
		fmt.Fprintf(&b, "destroy element %s %s { %s }\n", Table, e.Set, e.Key())
	}
	return b.String()
}

// Nft runs nft; rootd writes the sets only through it (one nft -f transaction per change).
type Nft struct{ Path string }

// Run applies a script as one transaction.
func (n Nft) Run(script string) error {
	if script == "" {
		return nil
	}
	c := exec.Command(n.Path, "-f", "-")
	c.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("nft: %v: %s", err, bytes.TrimSpace(stderr.Bytes()))
	}
	return nil
}

// List returns the element keys the kernel holds in set.
func (n Nft) List(set string) ([]string, error) {
	out, err := exec.Command(n.Path, "-j", "list", "set", "inet", "agentbox", set).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("nft list set %s: %v: %s", set, err, bytes.TrimSpace(ee.Stderr))
		}
		return nil, err
	}
	return ParseSetJSON(out)
}

// ParseSetJSON reads the "addr . port" elements of `nft -j list set` output.
func ParseSetJSON(b []byte) ([]string, error) {
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
	var keys []string
	for _, o := range doc.Nftables {
		if o.Set == nil {
			continue
		}
		for _, raw := range o.Set.Elem {
			// an element with a timeout is {"elem": {"val": {"concat": [...]}, "timeout": ..}}; without, the bare concat
			var e struct {
				Elem struct {
					Val json.RawMessage `json:"val"`
				} `json:"elem"`
				Concat []json.RawMessage `json:"concat"`
			}
			if err := json.Unmarshal(raw, &e); err != nil {
				return nil, err
			}
			cat := e.Concat
			if e.Elem.Val != nil {
				var v struct {
					Concat []json.RawMessage `json:"concat"`
				}
				if err := json.Unmarshal(e.Elem.Val, &v); err != nil {
					return nil, err
				}
				cat = v.Concat
			}
			var addr string
			var port int
			if len(cat) != 2 || json.Unmarshal(cat[0], &addr) != nil || json.Unmarshal(cat[1], &port) != nil || port < 0 || port > 65535 {
				return nil, fmt.Errorf("unexpected set element %s", raw)
			}
			a, err := netip.ParseAddr(addr)
			if err != nil {
				return nil, err
			}
			keys = append(keys, Elem{Addr: a, Port: uint16(port)}.Key())
		}
	}
	return keys, nil
}
