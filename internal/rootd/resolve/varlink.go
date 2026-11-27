package resolve

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// ResolvedSocket is systemd-resolved's Varlink service (io.systemd.Resolve).
const ResolvedSocket = "/run/systemd/resolve/io.systemd.Resolve"

// The resolved flags Appendix B requires: DNS only, no search domains, no synthesized records (local host name,
// _gateway, /etc/hosts) and no local zone (LLMNR and mDNS are off because only SD_RESOLVED_DNS is set).
const (
	sdResolvedDNS          = 1 << 0
	sdResolvedNoSearch     = 1 << 8
	sdResolvedNoSynthesize = 1 << 11
	sdResolvedNoZone       = 1 << 13
	ResolveFlags           = sdResolvedDNS | sdResolvedNoSearch | sdResolvedNoSynthesize | sdResolvedNoZone
)

// Reply flags that mark an answer resolved did not get over DNS (systemd src/shared/resolved-def.h). No request flag
// turns the hooks off: since systemd 259 any privileged service with a socket in /run/systemd/resolve.hook/ may answer
// (#145). ResolveFlags keep the other two out; they are checked again here.
const (
	sdResolvedSynthetic = 1 << 19 // /etc/hosts, localhost, _gateway
	sdResolvedFromZone  = 1 << 21 // the box's own LLMNR and mDNS records
	sdResolvedFromHook  = 1 << 27
)

// Refusal reasons a broker sees (§6.2 step 2). Addresses and the failed check never go to the broker.
const (
	NotAllowlisted = "not_allowlisted"
	NonPublic      = "non_public"
	NoSuchName     = "no_such_name"
	Unavailable    = "unavailable"
)

// Refused is a resolution refusal: Reason goes to the broker, Detail only to audit.
type Refused struct{ Reason, Detail string }

func (r *Refused) Error() string { return r.Reason + ": " + r.Detail }

// Varlink resolves through resolved's Varlink socket at Path.
type Varlink struct{ Path string }

// ResolveHostname returns every address resolved answers for name, in its order.
func (v Varlink) ResolveHostname(ctx context.Context, name string) ([]netip.Addr, error) {
	msg, err := varlinkCall(ctx, v.Path, "io.systemd.Resolve.ResolveHostname", map[string]any{"name": name, "flags": ResolveFlags})
	if err != nil {
		return nil, &Refused{Unavailable, err.Error()}
	}
	return parseVarlink(msg)
}

// varlinkCall sends one method call on the Varlink socket at path and returns its one reply.
func varlinkCall(ctx context.Context, path, method string, params map[string]any) ([]byte, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	} else {
		c.SetDeadline(time.Now().Add(30 * time.Second))
	}
	req, _ := json.Marshal(map[string]any{"method": method, "parameters": params})
	if _, err := c.Write(append(req, 0)); err != nil {
		return nil, err
	}
	msg, err := bufio.NewReader(c).ReadBytes(0)
	if err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(msg, []byte{0}), nil
}

func parseVarlink(msg []byte) ([]netip.Addr, error) {
	var raw struct {
		Parameters struct {
			Addresses []struct {
				Family  int   `json:"family"`
				Address []int `json:"address"`
			} `json:"addresses"`
			Rcode *int   `json:"rcode"`
			Flags uint64 `json:"flags"`
		} `json:"parameters"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(msg, &raw); err != nil {
		return nil, &Refused{Unavailable, "bad varlink reply: " + err.Error()}
	}
	switch raw.Error {
	case "":
	case "io.systemd.Resolve.NoSuchResourceRecord":
		return nil, &Refused{NoSuchName, raw.Error}
	case "io.systemd.Resolve.DNSError":
		if raw.Parameters.Rcode != nil && *raw.Parameters.Rcode == 3 { // NXDOMAIN
			return nil, &Refused{NoSuchName, raw.Error + " NXDOMAIN"}
		}
		return nil, &Refused{Unavailable, fmt.Sprintf("%s rcode %v", raw.Error, raw.Parameters.Rcode)}
	default:
		return nil, &Refused{Unavailable, raw.Error}
	}
	var out []netip.Addr
	for _, a := range raw.Parameters.Addresses {
		b := make([]byte, len(a.Address))
		for i, x := range a.Address {
			if x < 0 || x > 255 {
				return nil, &Refused{Unavailable, "bad address byte"}
			}
			b[i] = byte(x)
		}
		ip, ok := netip.AddrFromSlice(b)
		if !ok || (a.Family == 2) != ip.Is4() || (a.Family != 2 && a.Family != 10) {
			return nil, &Refused{Unavailable, "bad address in varlink reply"}
		}
		out = append(out, ip)
	}
	if len(out) == 0 {
		return nil, &Refused{NoSuchName, "no addresses"}
	}
	switch f := raw.Parameters.Flags; {
	case f&sdResolvedFromHook != 0:
		return nil, &Refused{NonPublic, fmt.Sprintf("from_hook (answers %v)", out)}
	case f&sdResolvedSynthetic != 0:
		return nil, &Refused{NonPublic, fmt.Sprintf("synthetic (answers %v)", out)}
	case f&sdResolvedFromZone != 0:
		return nil, &Refused{NonPublic, fmt.Sprintf("from_zone (answers %v)", out)}
	}
	return out, nil
}
