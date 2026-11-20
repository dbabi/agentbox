package nl

import (
	"golang.org/x/sys/unix"
)

// Do sends one request on a fresh netlink socket of protocol proto and returns the replies: every message of a dump
// up to NLMSG_DONE, or the single reply (or ACK) otherwise.
func Do(proto int, req []byte, dump bool) ([]Msg, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	var out []Msg
	for {
		buf := make([]byte, 1<<16) // fresh each time: the returned messages point into it
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, err
		}
		msgs, done, err := Parse(buf[:n])
		if err != nil {
			return nil, err
		}
		out = append(out, msgs...)
		if done || !dump {
			return out, nil
		}
	}
}
