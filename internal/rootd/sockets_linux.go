package rootd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"agentbox/internal/rootd/resolve"
)

// listeners takes the sockets systemd passed (sd_listen_fds): every one is a stream AF_UNIX socket named by its unit's
// FileDescriptorName=. rootd binds nothing itself: owner, group and mode come from the .socket units (§2.1).
func listeners() (map[string]*net.UnixListener, error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) {
		return nil, errors.New("no sockets from systemd (run as agentbox-rootd.service)")
	}
	n, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || n < 1 {
		return nil, errors.New("LISTEN_FDS: no sockets")
	}
	names := strings.Split(os.Getenv("LISTEN_FDNAMES"), ":")
	if len(names) != n {
		return nil, fmt.Errorf("LISTEN_FDNAMES has %d names for %d sockets", len(names), n)
	}
	for _, v := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		os.Unsetenv(v) // nft and other children must not see them
	}
	out := map[string]*net.UnixListener{}
	for i := 0; i < n; i++ {
		fd := 3 + i
		unix.CloseOnExec(fd)
		name := names[i]
		if name != sockAdmin && name != sockSeal && !(strings.HasPrefix(name, "resolve-") && slices.Contains(resolve.Brokers, name[8:])) {
			return nil, fmt.Errorf("unexpected socket %q", name)
		}
		ln, err := net.FileListener(os.NewFile(uintptr(fd), name))
		if err != nil {
			return nil, fmt.Errorf("socket %s: %v", name, err)
		}
		ul, ok := ln.(*net.UnixListener)
		if !ok {
			return nil, fmt.Errorf("socket %s is not AF_UNIX", name)
		}
		out[name] = ul
	}
	return out, nil
}

type peer struct {
	uid    uint32
	groups []uint32
}

func peerCred(c *net.UnixConn) (peer, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return peer{}, err
	}
	var p peer
	var serr error
	err = raw.Control(func(fd uintptr) {
		var uc *unix.Ucred
		if uc, serr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED); serr != nil {
			return
		}
		p.uid = uc.Uid
		p.groups = append(p.groups, uc.Gid)
		buf := make([]uint32, 1024)
		l := uint32(len(buf) * 4)
		if _, _, e := unix.Syscall6(unix.SYS_GETSOCKOPT, fd, unix.SOL_SOCKET, unix.SO_PEERGROUPS,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&l)), 0); e != 0 {
			serr = e
			return
		}
		p.groups = append(p.groups, buf[:l/4]...)
	})
	if err == nil {
		err = serr
	}
	return p, err
}

// allowed is the SO_PEERCRED check for each socket (§2.1): admin takes uid 0 and agentbox-admin members (by the
// peer's own supplementary groups at connect, SO_PEERGROUPS); resolve-<svc> takes only agentbox-<svc>; seal takes only
// agentbox-audit. A missing user or group admits nobody.
func allowed(sock string, p peer) bool {
	switch {
	case sock == sockAdmin:
		g, ok := lookupGID("agentbox-admin")
		return p.uid == 0 || ok && slices.Contains(p.groups, g)
	case sock == sockSeal:
		u, ok := lookupUID("agentbox-audit")
		return ok && p.uid == u
	case strings.HasPrefix(sock, "resolve-"):
		u, ok := lookupUID("agentbox-" + sock[8:])
		return ok && p.uid == u
	}
	return false
}

func (s *server) accept(name string, ln *net.UnixListener) {
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("%s: accept: %v", name, err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go s.serve(name, c)
	}
}

const maxLine = 64 << 10

// serve reads newline-delimited JSON requests and writes one JSON reply line each. Ancillary data of any kind
// (SCM_RIGHTS included) closes the connection: rootd takes no descriptors (§2.1).
func (s *server) serve(name string, c *net.UnixConn) {
	defer c.Close()
	p, err := peerCred(c)
	if err != nil || !allowed(name, p) {
		log.Printf("%s: refused peer uid=%d groups=%v: %v", name, p.uid, p.groups, err)
		return
	}
	var buf []byte
	b := make([]byte, 4096)
	oob := make([]byte, unix.CmsgSpace(64*4))
	for {
		c.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, oobn, flags, _, err := c.ReadMsgUnix(b, oob)
		if oobn > 0 || flags&unix.MSG_CTRUNC != 0 {
			closeRights(oob[:oobn])
			log.Printf("%s: uid %d sent ancillary data: connection closed", name, p.uid)
			return
		}
		buf = append(buf, b[:n]...)
		for {
			i := bytes.IndexByte(buf, '\n')
			if i < 0 {
				break
			}
			var r request
			dec := json.NewDecoder(bytes.NewReader(buf[:i]))
			dec.DisallowUnknownFields()
			rep := fail("bad_request")
			if dec.Decode(&r) == nil {
				rep = s.handle(name, r)
			}
			if _, err := c.Write(encode(rep)); err != nil {
				return
			}
			buf = buf[i+1:]
		}
		if len(buf) > maxLine || err != nil {
			return
		}
	}
}

func closeRights(oob []byte) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return
	}
	for _, m := range msgs {
		if fds, err := unix.ParseUnixRights(&m); err == nil {
			for _, fd := range fds {
				syscall.Close(fd)
			}
		}
	}
}
