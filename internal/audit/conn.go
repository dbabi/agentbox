package audit

import (
	"bufio"
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

var errFDPassing = errors.New("refused: ancillary data (SCM_RIGHTS)")

// fdFree reads a Unix stream and fails on any ancillary data: servers refuse descriptor passing (§2.1).
type fdFree struct{ c *net.UnixConn }

func (f fdFree) Read(p []byte) (int, error) {
	oob := make([]byte, 64)
	n, oobn, _, _, err := f.c.ReadMsgUnix(p, oob)
	if oobn > 0 {
		// the kernel has already installed any passed descriptors in this process: close them
		if msgs, perr := unix.ParseSocketControlMessage(oob[:oobn]); perr == nil {
			for _, m := range msgs {
				if fds, err := unix.ParseUnixRights(&m); err == nil {
					for _, fd := range fds {
						unix.Close(fd)
					}
				}
			}
		}
		return 0, errFDPassing
	}
	return n, err
}

var errLineTooLong = errors.New("record too long")

// readLine reads one "\n"-terminated line of at most max bytes, without the "\n".
func readLine(r *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > max+1 {
			return nil, errLineTooLong
		}
		if err == nil {
			return line[:len(line)-1], nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
	}
}
