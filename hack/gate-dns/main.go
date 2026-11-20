// Command gate-dns is a test DNS server for hack/rootd-gate.sh, run inside the test VM: it answers A and AAAA queries
// for names under -zone, and for any other name, from -a flags (NXDOMAIN for any other name in the zone), and relays every other query to
// -upstream unchanged, so the box keeps working while resolved uses it as its only server. Test fixture: never shipped.
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"
)

type records map[string][]netip.Addr

type multi []string

func (m *multi) String() string     { return strings.Join(*m, " ") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	listen := flag.String("listen", "127.0.0.153:53", "UDP and TCP listen address (loopback only)")
	upstream := flag.String("upstream", "10.0.2.3:53", "where other queries go")
	zone := flag.String("zone", "gate.test", "zone answered here")
	var as multi
	flag.Var(&as, "a", "name=addr[,addr...] (repeatable)")
	flag.Parse()
	recs, err := parseRecords(as)
	if err != nil {
		log.Fatal(err)
	}
	if ap, err := netip.ParseAddrPort(*listen); err != nil || !ap.Addr().IsLoopback() {
		log.Fatalf("-listen %s: must be a loopback address:port", *listen)
	}
	pc, err := net.ListenPacket("udp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	h := func(q []byte) []byte {
		if r, ok := answer(q, strings.ToLower(*zone), recs); ok {
			return r
		}
		r, err := relay(q, *upstream)
		if err != nil {
			log.Printf("relay: %v", err)
		}
		return r
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				log.Fatal(err)
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				var l [2]byte
				if _, err := io.ReadFull(c, l[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				if r := h(q); r != nil {
					c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(r))), r...))
				}
			}()
		}
	}()
	fmt.Fprintln(os.Stderr, "gate-dns: serving", *zone, "on", *listen)
	buf := make([]byte, 4096)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			log.Fatal(err)
		}
		q := append([]byte(nil), buf[:n]...)
		go func() {
			if r := h(q); r != nil {
				pc.WriteTo(r, from)
			}
		}()
	}
}

func parseRecords(as []string) (records, error) {
	recs := records{}
	for _, a := range as {
		name, list, ok := strings.Cut(a, "=")
		if !ok {
			return nil, fmt.Errorf("-a %q: want name=addr[,addr]", a)
		}
		for _, s := range strings.Split(list, ",") {
			ip, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("-a %q: %v", a, err)
			}
			recs[strings.ToLower(name)] = append(recs[strings.ToLower(name)], ip)
		}
	}
	return recs, nil
}

func relay(q []byte, upstream string) ([]byte, error) {
	c, err := net.DialTimeout("udp", upstream, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	b := make([]byte, 4096)
	n, err := c.Read(b)
	return b[:n], err
}

// question returns the query's name (lower case), type, and the end offset of its one question.
func question(q []byte) (string, uint16, int, error) {
	if len(q) < 12 || binary.BigEndian.Uint16(q[4:]) != 1 {
		return "", 0, 0, errors.New("want one question")
	}
	var labels []string
	i := 12
	for {
		if i >= len(q) {
			return "", 0, 0, errors.New("short name")
		}
		l := int(q[i])
		if l == 0 {
			i++
			break
		}
		if l > 63 || i+1+l > len(q) {
			return "", 0, 0, errors.New("bad label")
		}
		labels = append(labels, strings.ToLower(string(q[i+1:i+1+l])))
		i += 1 + l
	}
	if i+4 > len(q) {
		return "", 0, 0, errors.New("short question")
	}
	return strings.Join(labels, "."), binary.BigEndian.Uint16(q[i:]), i + 4, nil
}

// answer builds the reply for a query in zone; ok is false for names outside it.
func answer(q []byte, zone string, recs records) ([]byte, bool) {
	name, qtype, end, err := question(q)
	addrs, known := recs[name] // a name given with -a is answered even outside the zone (ipv4only.arpa)
	if err != nil || (!known && name != zone && !strings.HasSuffix(name, "."+zone)) {
		return nil, false
	}
	r := append([]byte(nil), q[:end]...)
	flags := uint16(0x8400) | binary.BigEndian.Uint16(q[2:])&0x0100 | 0x0080 // QR AA, copy RD, RA
	if !known {
		flags |= 3 // NXDOMAIN
	}
	binary.BigEndian.PutUint16(r[2:], flags)
	var n uint16
	for _, a := range addrs {
		t := uint16(1)
		if a.Is6() {
			t = 28
		}
		if t != qtype {
			continue
		}
		r = append(r, 0xc0, 12)
		r = binary.BigEndian.AppendUint16(r, t)
		r = binary.BigEndian.AppendUint16(r, 1)
		r = binary.BigEndian.AppendUint32(r, 30)
		r = binary.BigEndian.AppendUint16(r, uint16(len(a.AsSlice())))
		r = append(r, a.AsSlice()...)
		n++
	}
	binary.BigEndian.PutUint16(r[6:], n)
	binary.BigEndian.PutUint16(r[8:], 0)
	var ar uint16
	if binary.BigEndian.Uint16(q[10:]) > 0 { // the query has an OPT record: answer EDNS0 so resolved keeps its feature level
		r = append(r, 0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0)
		ar = 1
	}
	binary.BigEndian.PutUint16(r[10:], ar)
	return r, true
}
