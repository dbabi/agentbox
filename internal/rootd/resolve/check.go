// Package resolve is rootd's resolver (ARCHITECTURE.md §6.1, §6.3, Appendix B): it resolves allowlisted host:port
// names through systemd-resolved's Varlink socket, refuses any name with a non-public answer, and hands the answers to
// the broker destination sets. Brokers use Client on their resolve-<svc>.sock.
package resolve

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"agentbox/internal/fw"
)

// Appendix B's private4 and private6 sets come from fw's one list: the nft sets the firewall loads, and fwcheck
// compares them to it.
var (
	private4, private6 = prefixes(fw.Private4), prefixes(fw.Private6)
	nat64              = netip.MustParsePrefix("64:ff9b::/96")
)

func prefixes(s []string) []netip.Prefix {
	p := make([]netip.Prefix, len(s))
	for i, v := range s {
		p[i] = netip.MustParsePrefix(v)
	}
	return p
}

func inAny(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// CheckPrefix is Appendix B checks 1 and 2: the address is in no special-purpose range, and a well-known-prefix NAT64
// address does not wrap one. Other NAT64 addresses pass, so NAT64-only LANs work. It returns the failed check's name,
// which goes only to audit detail.
func CheckPrefix(a netip.Addr) string {
	if a.Zone() != "" {
		return "zoned"
	}
	if a.Is4() {
		if inAny(a, private4) {
			return "private4"
		}
		return ""
	}
	if inAny(a, private6) {
		return "private6"
	}
	if nat64.Contains(a) {
		b := a.As16()
		if inAny(netip.AddrFrom4([4]byte(b[12:])), private4) {
			return "nat64_private"
		}
	}
	return ""
}

// Entry is one allowlisted host:port, IDNA-canonical: ASCII A-labels, lower case.
type Entry struct {
	Host string
	Port uint16
}

func (e Entry) String() string { return e.Host + ":" + strconv.Itoa(int(e.Port)) }

// ParseEntry accepts host:port with an LDH host name of at least two labels (A-labels; no IP literals, wildcards or
// trailing dot) and a port 1-65535. Upper case is folded: an allowlist names hosts, not spellings.
func ParseEntry(s string) (Entry, error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return Entry{}, fmt.Errorf("%q: want host:port", s)
	}
	host, ps := strings.ToLower(s[:i]), s[i+1:]
	p, err := strconv.ParseUint(ps, 10, 16)
	if err != nil || p == 0 || ps[0] == '0' {
		return Entry{}, fmt.Errorf("%q: port must be 1-65535", s)
	}
	if err := checkHost(host); err != nil {
		return Entry{}, fmt.Errorf("%q: %v", s, err)
	}
	return Entry{host, uint16(p)}, nil
}

func checkHost(h string) error {
	if len(h) > 253 {
		return errors.New("host name too long")
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return errors.New("host needs at least two labels")
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return errors.New("host is not an ASCII LDH name")
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return errors.New("host is not an ASCII LDH name (IDNA A-labels only)")
			}
		}
	}
	if _, err := netip.ParseAddr(h); err == nil || strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return errors.New("host is an IP literal")
	}
	return nil
}
