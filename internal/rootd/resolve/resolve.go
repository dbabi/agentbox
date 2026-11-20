// Package resolve is rootd's name resolution for the nft destination sets (ARCHITECTURE.md §6.1, Appendix B):
// systemd-resolved's Varlink API over its Unix socket, then the Appendix B insert checks on every answer.
package resolve

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

const varlinkSocket = "/run/systemd/resolve/io.systemd.Resolve"

// systemd's resolved-def.h. DNS only: no LLMNR, mDNS, /etc/hosts, _gateway or local-hostname answers (Appendix B).
const (
	flagDNS          = 1 << 0
	flagNoSearch     = 1 << 8
	flagNoSynthesize = 1 << 11
	flagNoZone       = 1 << 13
	Flags            = flagDNS | flagNoSearch | flagNoSynthesize | flagNoZone
)

// Private4 and Private6 are the IANA special-purpose ranges of Appendix B's private4 and private6 sets. The nft sets
// and this table come from this one list; fwcheck compares them.
var (
	Private4 = prefixes("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3")
	Private6 = prefixes("::/127", "::ffff:0:0/96", "64:ff9b:1::/48", "100::/64", "2001:db8::/32", "fc00::/7",
		"fe80::/10", "fec0::/10", "ff00::/8")
	nat64 = netip.MustParsePrefix("64:ff9b::/96")
)

// Linux values: Varlink sends them as numbers, and syscall's differ on other systems
const (
	rtnUnicast = 1 // RTN_UNICAST
	afInet     = 2
	afInet6    = 10
)

func prefixes(s ...string) []netip.Prefix {
	p := make([]netip.Prefix, len(s))
	for i, v := range s {
		p[i] = netip.MustParsePrefix(v)
	}
	return p
}

// Hostname asks resolved for name's A and AAAA answers with Flags.
func Hostname(name string) ([]netip.Addr, error) {
	return hostname(varlinkSocket, name)
}

func hostname(sock, name string) ([]netip.Addr, error) {
	c, err := net.DialTimeout("unix", sock, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	req, _ := json.Marshal(map[string]any{"method": "io.systemd.Resolve.ResolveHostname",
		"parameters": map[string]any{"name": name, "flags": Flags}})
	if _, err := c.Write(append(req, 0)); err != nil { // Varlink frames end in a NUL byte
		return nil, err
	}
	msg, err := bufio.NewReader(c).ReadBytes(0)
	if err != nil {
		return nil, err
	}
	// []byte would expect base64; Varlink sends the address as an array of numbers
	var raw struct {
		Error      string          `json:"error"`
		Parameters json.RawMessage `json:"parameters"`
	}
	if err := json.Unmarshal(msg[:len(msg)-1], &raw); err != nil {
		return nil, fmt.Errorf("resolve %s: bad Varlink reply: %v", name, err)
	}
	if raw.Error != "" {
		return nil, fmt.Errorf("resolve %s: %s", name, raw.Error)
	}
	var p struct {
		Addresses []struct {
			Family  int   `json:"family"`
			Address []int `json:"address"`
		} `json:"addresses"`
	}
	if err := json.Unmarshal(raw.Parameters, &p); err != nil {
		return nil, fmt.Errorf("resolve %s: bad Varlink reply: %v", name, err)
	}
	var out []netip.Addr
	for _, a := range p.Addresses {
		b := make([]byte, len(a.Address))
		for i, v := range a.Address {
			if v < 0 || v > 255 {
				return nil, fmt.Errorf("resolve %s: bad address byte %d", name, v)
			}
			b[i] = byte(v)
		}
		ip, ok := netip.AddrFromSlice(b)
		if !ok || (a.Family == afInet) != (len(b) == 4) || (a.Family != afInet && a.Family != afInet6) {
			return nil, fmt.Errorf("resolve %s: bad address %v (family %d)", name, a.Address, a.Family)
		}
		out = append(out, ip)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("resolve %s: no addresses", name)
	}
	return out, nil
}

// CheckPrefix is Appendix B checks 1 and 2: not special-purpose, and no NAT64 address that embeds one.
func CheckPrefix(a netip.Addr) error {
	list := Private6
	if a.Is4() {
		list = Private4
	}
	for _, p := range list {
		if p.Contains(a) {
			return fmt.Errorf("%s is in special-purpose range %s", a, p)
		}
	}
	if nat64.Contains(a) {
		b := a.As16()
		v4 := netip.AddrFrom4([4]byte(b[12:]))
		for _, p := range Private4 {
			if p.Contains(v4) {
				return fmt.Errorf("%s is NAT64 for %s, in special-purpose range %s", a, v4, p)
			}
		}
	}
	return nil
}

// Check runs all three Appendix B checks on a: the prefix checks, then check 3, the route: RTM_GETROUTE must return a
// unicast route out of the default route's interface, with a gateway whenever the default route has one. That
// rejects addresses that look public by prefix but are on-link LAN or tailnet-routed.
func Check(a netip.Addr) error {
	if err := CheckPrefix(a); err != nil {
		return err
	}
	def, err := defaultRoute(a.Is4())
	if err != nil {
		return err
	}
	r, err := getRoute(a)
	if err != nil {
		return err
	}
	return checkRoute(a, r, def)
}

// ErrNoDefaultRoute: the box has no default route for the address's family, so it can't reach the address at all.
var ErrNoDefaultRoute = errors.New("no default route")

type route struct {
	typ uint8
	oif uint32
	gw  bool
}

func checkRoute(a netip.Addr, r, def route) error {
	switch {
	case r.typ != rtnUnicast:
		return fmt.Errorf("%s: route type %d is not unicast", a, r.typ)
	case r.oif != def.oif:
		return fmt.Errorf("%s: routed out of interface %d, not the default route's %d", a, r.oif, def.oif)
	case def.gw && !r.gw:
		return fmt.Errorf("%s: on-link (no gateway), but the default route has one", a)
	}
	return nil
}
