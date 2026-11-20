package nl

import (
	"errors"
	"net/netip"
	"syscall"

	"golang.org/x/sys/unix"
)

// DeleteFlows deletes every TCP conntrack entry whose original destination is dst:port and returns how many went.
// An entry that is already gone (it closed meanwhile) is not an error.
func DeleteFlows(dst netip.Addr, port uint16) (int, error) {
	msgs, err := Do(unix.NETLINK_NETFILTER, CTDumpReq(1, dst), true)
	if err != nil {
		return 0, err
	}
	reqs, err := CTDeleteReqs(1, msgs, dst, port)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range reqs {
		if _, err := Do(unix.NETLINK_NETFILTER, r, false); err != nil {
			if errors.Is(err, syscall.ENOENT) {
				continue
			}
			return n, err
		}
		n++
	}
	return n, nil
}
