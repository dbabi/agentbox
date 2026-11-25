package resolve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"agentbox/internal/rootd/gens"
)

// NetworkdSocket is systemd-networkd's Varlink service (io.systemd.Network).
const NetworkdSocket = "/run/systemd/netif/io.systemd.Network"

// Pref64DropIn is the drop-in agentbox-reconcile gives every .network file. networkd records the PREF64 options of
// router advertisements only with UsePREF64=yes, which defaults to no, and netplan has no key for it.
const Pref64DropIn = "90-agentbox-pref64.conf"

const pref64Conf = "# Written by agentbox-reconcile (ARCHITECTURE.md Appendix B check 2).\n[IPv6AcceptRA]\nUsePREF64=yes\n"

// NetworkDirs are the directories networkd reads .network files from (systemd.network(5)), /etc first.
var NetworkDirs = []string{"/etc/systemd/network", "/run/systemd/network", "/usr/local/lib/systemd/network", "/usr/lib/systemd/network"}

// ipv4only.arpa's A records (RFC 7050): a DNS64 resolver wraps them in its NAT64 prefix.
var wka = []netip.Addr{netip.MustParseAddr("192.0.0.170"), netip.MustParseAddr("192.0.0.171")}

// NAT64Prefixes finds the network's own NAT64 prefixes at resolve time, so check 2 can unwrap addresses under them as
// it does under 64:ff9b::/96: the PREF64 options networkd learned from router advertisements (RFC 8781, pref64), and
// the prefix DNS64 wraps ipv4only.arpa in (RFC 7050), looked up through resolve.
func NAT64Prefixes(ctx context.Context, resolve func(context.Context, string) ([]netip.Addr, error),
	pref64 func(context.Context) ([]netip.Prefix, error)) ([]netip.Prefix, error) {
	var out []netip.Prefix
	if pref64 != nil {
		p, err := pref64(ctx)
		if err != nil {
			return nil, fmt.Errorf("networkd PREF64: %w", err)
		}
		out = append(out, p...)
	}
	// ipv4only.arpa always has A records, so any failure (NXDOMAIN and no records included) is a failed lookup that
	// would hide the network's prefix; only A records with no wrapping AAAA mean no DNS64 (Appendix B check 2)
	addrs, err := resolve(ctx, "ipv4only.arpa")
	if err != nil {
		return nil, fmt.Errorf("ipv4only.arpa: %w", err)
	}
	for _, a := range addrs {
		for _, bits := range []int{96, 64, 56, 48, 40, 32} {
			p := netip.PrefixFrom(a, bits).Masked()
			if v4, ok := embedded4(a, p); ok && (v4 == wka[0] || v4 == wka[1]) {
				out = append(out, p)
				break
			}
		}
	}
	return out, nil
}

// Networkd reads networkd's state over its Varlink socket at Path.
type Networkd struct{ Path string }

// Pref64 returns every PREF64 prefix networkd holds, on any link. A box without networkd has none. A link networkd
// runs without Pref64DropIn is an error: networkd drops the PREF64 options it receives there, so the network's prefix
// would be missing, not absent.
func (n Networkd) Pref64(ctx context.Context) ([]netip.Prefix, error) {
	msg, err := varlinkCall(ctx, n.Path, "io.systemd.Network.Describe", map[string]any{})
	if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return parsePref64(msg)
}

func parsePref64(msg []byte) ([]netip.Prefix, error) {
	var raw struct {
		Parameters struct {
			Interfaces []struct {
				Name               string
				NetworkFile        string
				NetworkFileDropins []string
				NDisc              struct {
					PREF64 []struct {
						Prefix       []int
						PrefixLength int
					}
				}
			}
		} `json:"parameters"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(msg, &raw); err != nil {
		return nil, fmt.Errorf("bad varlink reply: %v", err)
	}
	if raw.Error != "" {
		return nil, errors.New(raw.Error)
	}
	var out []netip.Prefix
	for _, l := range raw.Parameters.Interfaces {
		if l.NetworkFile != "" && !slices.ContainsFunc(l.NetworkFileDropins, func(d string) bool { return filepath.Base(d) == Pref64DropIn }) {
			return nil, fmt.Errorf("%s runs %s without %s, so networkd records no PREF64 on it", l.Name, l.NetworkFile, Pref64DropIn)
		}
		for _, p := range l.NDisc.PREF64 {
			b := make([]byte, len(p.Prefix))
			ok := true
			for i, x := range p.Prefix {
				ok = ok && x >= 0 && x <= 255
				b[i] = byte(x)
			}
			a, isAddr := netip.AddrFromSlice(b)
			ok = ok && isAddr
			pp, err := a.Prefix(p.PrefixLength)
			if !ok || !a.Is6() || err != nil {
				return nil, fmt.Errorf("bad PREF64 %v/%d", p.Prefix, p.PrefixLength)
			}
			out = append(out, pp)
		}
	}
	return out, nil
}

// WritePref64DropIns gives every .network file in dirs the drop-in dirs[0]/<name>.network.d/Pref64DropIn. It reports
// whether it wrote one, so the caller knows networkd must reload.
func WritePref64DropIns(dirs []string) (bool, error) {
	changed := false
	for _, d := range dirs {
		names, err := filepath.Glob(filepath.Join(d, "*.network"))
		if err != nil {
			return changed, err
		}
		for _, n := range names {
			p := filepath.Join(dirs[0], filepath.Base(n)+".d", Pref64DropIn)
			if b, err := os.ReadFile(p); err == nil && string(b) == pref64Conf {
				continue
			}
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				return changed, err
			}
			if err := gens.WriteAtomic(p, []byte(pref64Conf), 0o644); err != nil {
				return changed, err
			}
			changed = true
		}
	}
	return changed, nil
}
