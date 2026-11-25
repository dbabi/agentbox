package hack

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

var (
	guestMAC = []byte{0x52, 0x54, 0, 0x12, 0x34, 0x56}
	guest4   = netip.MustParseAddr("10.0.2.15")
	guest6   = netip.MustParseAddr("fec0::15")
)

// TestVMNetLoopback builds hack/vmnet against this host's libslirp and runs it with this test binary as QEMU
// (TestVMNetGuest). As root in the guest could, the fake guest sends raw frames: a TCP SYN and a UDP datagram to the
// probe port at each address that a host socket takes as the host itself. Listeners on 127.0.0.1 and ::1 at that port
// must see none of them: libslirp 4.9.1 (Ubuntu 26.04's) connects to each address as given. As a control, the guest
// then connects to 10.0.2.2:FWD, a forward, which must reach 127.0.0.1:FWD, so libslirp took the guest's frames.
func TestVMNetLoopback(t *testing.T) {
	flags, err := exec.Command("pkg-config", "--cflags", "--libs", "slirp").Output()
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("CI needs libslirp-dev, libglib2.0-dev and pkgconf")
		}
		t.Skip("libslirp not found")
	}
	v, _ := exec.Command("pkg-config", "--modversion", "slirp").Output()
	t.Logf("libslirp %s", bytes.TrimSpace(v))
	vmnet := filepath.Join(t.TempDir(), "vmnet")
	cc := append([]string{"-O2", "-Wall", "-o", vmnet, filepath.Join("vmnet", "vmnet.c")}, strings.Fields(string(flags))...)
	if b, err := exec.Command("cc", cc...).CombinedOutput(); err != nil {
		t.Fatalf("cc: %v\n%s", err, b)
	}

	hits := make(chan string, 64)
	tcp := func(l net.Listener) {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			hits <- "tcp from " + c.RemoteAddr().String() + " to " + c.LocalAddr().String()
			c.Close()
		}
	}
	listen := func(network, addr string) net.Listener {
		l, err := net.Listen(network, addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		return l
	}
	probe := listen("tcp4", "127.0.0.1:0")
	port := strconv.Itoa(probe.Addr().(*net.TCPAddr).Port)
	go tcp(probe)
	for _, a := range []string{"udp4 127.0.0.1", "udp6 ::1"} {
		n, ip, _ := strings.Cut(a, " ")
		u, err := net.ListenPacket(n, net.JoinHostPort(ip, port))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { u.Close() })
		go func() {
			b := make([]byte, 512)
			for {
				_, from, err := u.ReadFrom(b)
				if err != nil {
					return
				}
				hits <- "udp from " + from.String() + " to " + u.LocalAddr().String()
			}
		}()
	}
	go tcp(listen("tcp6", "[::1]:"+port))
	fwd := listen("tcp4", "127.0.0.1:0")
	ssh := listen("tcp4", "127.0.0.1:0") // a free port for vmnet's SSH forward, which nothing uses here
	sshPort := strconv.Itoa(ssh.Addr().(*net.TCPAddr).Port)
	ssh.Close()

	fwdPort := strconv.Itoa(fwd.Addr().(*net.TCPAddr).Port)
	cmd := exec.Command(vmnet, sshPort, fwdPort, "--", os.Args[0], "-test.run=^TestVMNetGuest$")
	cmd.Env = append(os.Environ(), "VMNET_GUEST="+port+" "+fwdPort)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	ctl := make(chan net.Conn, 1)
	go func() {
		if c, err := fwd.Accept(); err == nil {
			ctl <- c
		}
	}()
	select {
	case c := <-ctl:
		c.Close()
	case <-time.After(20 * time.Second):
		t.Fatalf("the control connection to 10.0.2.2:%s never reached 127.0.0.1:%s:\n%s", fwdPort, fwdPort, out.String())
	}
	// the probes went out before the control's SYN, so any hit has had the control's round trip and this second
	time.Sleep(time.Second)
	for {
		select {
		case h := <-hits:
			t.Errorf("the guest reached the host's loopback: %s", h)
		default:
			return
		}
	}
}

// TestVMNetGuest is TestVMNetLoopback's QEMU. vmnet gives it the guest's end of the network as fd 3: frames, each
// after its length as 4 bytes big-endian.
func TestVMNetGuest(t *testing.T) {
	ports := strings.Fields(os.Getenv("VMNET_GUEST"))
	if len(ports) != 2 {
		return // not run as the fake QEMU
	}
	time.AfterFunc(time.Minute, func() { os.Exit(0) }) // TestVMNetLoopback kills it long before
	probe, _ := strconv.Atoi(ports[0])
	fwd, _ := strconv.Atoi(ports[1])
	f := os.NewFile(3, "vmnet")
	send := func(typ uint16, b []byte) {
		h := binary.BigEndian.AppendUint32(nil, uint32(14+len(b)))
		h = append(append([]byte(h), 0xff, 0xff, 0xff, 0xff, 0xff, 0xff), guestMAC...) // libslirp takes any destination MAC
		if _, err := f.Write(append(binary.BigEndian.AppendUint16(h, typ), b...)); err != nil {
			t.Fatal(err)
		}
	}
	// a gratuitous ARP, so libslirp can send to the guest
	arp := append([]byte{0, 1, 8, 0, 6, 4, 0, 1}, guestMAC...)
	arp = append(append(append(arp, guest4.AsSlice()...), 0, 0, 0, 0, 0, 0), guest4.AsSlice()...)
	send(0x0806, arp)
	for _, a := range []string{"127.0.0.1", "127.1.2.3", "0.0.0.0", "::1", "::", "::ffff:127.0.0.1", "::127.0.0.1"} {
		send(packet(netip.MustParseAddr(a), 6, 40001, uint16(probe), 1, 0, 0x02)) // SYN
		send(packet(netip.MustParseAddr(a), 17, 40001, uint16(probe), 0, 0, 0))
	}
	gw := netip.MustParseAddr("10.0.2.2")
	send(packet(gw, 6, 40000, uint16(fwd), 1000, 0, 0x02))
	var buf []byte
	for b := make([]byte, 65536); ; {
		n, err := f.Read(b)
		if err != nil {
			if err != io.EOF {
				t.Fatal(err)
			}
			return
		}
		buf = append(buf, b[:n]...)
		for len(buf) >= 4 && len(buf) >= 4+int(binary.BigEndian.Uint32(buf)) {
			fr := buf[4 : 4+binary.BigEndian.Uint32(buf)]
			buf = buf[4+len(fr):]
			// the SYN-ACK from 10.0.2.2:FWD: ACK it, and libslirp starts vmnet's relay to 127.0.0.1:FWD
			if len(fr) < 14+20+20 || binary.BigEndian.Uint16(fr[12:]) != 0x0800 || fr[14+9] != 6 {
				continue
			}
			tcp := fr[14+int(fr[14]&15)*4:]
			if len(tcp) >= 20 && int(binary.BigEndian.Uint16(tcp)) == fwd && binary.BigEndian.Uint16(tcp[2:]) == 40000 && tcp[13]&0x12 == 0x12 {
				send(packet(gw, 6, 40000, uint16(fwd), 1001, binary.BigEndian.Uint32(tcp[4:])+1, 0x10))
			}
		}
	}
}

// packet is the guest's IPv4 or IPv6 packet to dst: a TCP segment with no data, or (proto 17) a 1-byte UDP datagram.
func packet(dst netip.Addr, proto byte, sport, dport uint16, seq, ack uint32, flags byte) (uint16, []byte) {
	l4 := binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(nil, sport), dport)
	sum := 16 // the checksum's offset
	if proto == 6 {
		l4 = binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint32(l4, seq), ack)
		l4 = append(l4, 5<<4, flags, 0xff, 0xff, 0, 0, 0, 0) // data offset, flags, window, checksum, urgent pointer
	} else {
		l4, sum = append(l4, 0, 9, 0, 0, 'x'), 6 // length, checksum, data
	}
	src := guest4
	if !dst.Is4() {
		src = guest6
	}
	s, d := src.AsSlice(), dst.AsSlice()
	// zero, protocol and length: the same 16-bit words as the IPv6 pseudo-header's length and next header
	c := checksum(append(append(append(append([]byte{}, s...), d...), 0, proto, 0, byte(len(l4))), l4...))
	if c == 0 && proto == 17 {
		c = 0xffff // 0 means no checksum in UDP over IPv4
	}
	binary.BigEndian.PutUint16(l4[sum:], c)
	if dst.Is4() {
		h := append([]byte{0x45, 0, 0, byte(20 + len(l4)), 0, 0, 0, 0, 64, proto, 0, 0}, append(s, d...)...)
		binary.BigEndian.PutUint16(h[10:], checksum(h))
		return 0x0800, append(h, l4...)
	}
	h := append([]byte{0x60, 0, 0, 0, 0, byte(len(l4)), proto, 64}, append(s, d...)...)
	return 0x86dd, append(h, l4...)
}

func checksum(b []byte) uint16 {
	var s uint32
	for i := 0; i < len(b); i += 2 {
		s += uint32(b[i]) << 8
		if i+1 < len(b) {
			s += uint32(b[i+1])
		}
	}
	for s > 0xffff {
		s = s>>16 + s&0xffff
	}
	return ^uint16(s)
}
