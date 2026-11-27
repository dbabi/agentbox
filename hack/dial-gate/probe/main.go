// Command probe is hack/dial-gate.sh's helper inside the test VM, built for the guest. It stands in for a broker until
// the brokers land: resolve, dial and get use internal/dial, the brokers' pinned dialing, on a rootd resolve socket.
// Test fixture: never shipped.
//
//	probe resolve SOCK HOST:PORT     dial.Resolve as the calling uid. Prints "addrs ADDR..." in rootd's order, or
//	                                 "refused REASON"
//	probe dial SOCK HOST:PORT        Dialer.DialContext. Prints "connected ADDR:PORT", "refused REASON" (rootd's), or
//	                                 "failed WHAT MS" (no address answered, after MS ms)
//	probe get SOCK URL CA            one GET through Dialer.Client, trusting only the CA PEM file. Prints "status CODE
//	                                 BODY", "redirect" for a redirect it did not follow, "error ERR", or what dial
//	                                 prints for a refusal or a failed dial
//	probe serve DIR NAMES ADDR...    a TLS server on each ADDR (host:port) with a new self-signed certificate for the
//	                                 comma-separated NAMES, written to DIR/ca.pem. It answers "pinned LOCAL", and /moved
//	                                 with a redirect. Logs "accept LOCAL" for every TCP connection and "get LOCAL
//	                                 sni=SNI host=HOST" for every request on stdout
//	probe ra IFACE PREFIX            one router advertisement out of IFACE to ff02::1: router lifetime 0 (no default
//	                                 route) and a prefix option for PREFIX (a /64, on-link and autonomous), which SLAAC
//	                                 configures
//
// A refusal, a failed dial, a redirect and an error exit 3.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"agentbox/internal/dial"
	"agentbox/internal/rootd/resolve"
)

func main() {
	log.SetFlags(0)
	a := os.Args[1:]
	switch {
	case len(a) == 3 && a[0] == "resolve":
		host, p, err := net.SplitHostPort(a[2])
		if err != nil {
			log.Fatal(err)
		}
		port, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			log.Fatal(err)
		}
		addrs, err := dial.Resolve(context.Background(), a[1], "", host, uint16(port))
		if err != nil {
			fail(err, time.Now())
		}
		s := make([]string, len(addrs))
		for i, ad := range addrs {
			s[i] = ad.String()
		}
		fmt.Println("addrs", strings.Join(s, " "))
	case len(a) == 3 && a[0] == "dial":
		start := time.Now()
		c, err := dial.Dialer{Sock: a[1]}.DialContext(context.Background(), "tcp", a[2])
		if err != nil {
			fail(err, start)
		}
		fmt.Println("connected", c.RemoteAddr())
		c.Close()
	case len(a) == 4 && a[0] == "get":
		pem, err := os.ReadFile(a[3])
		if err != nil {
			log.Fatal(err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			log.Fatalf("%s: no certificate", a[3])
		}
		c := dial.Dialer{Sock: a[1]}.Client()
		c.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: roots}
		start := time.Now()
		resp, err := c.Get(a[2])
		if err != nil {
			fail(err, start)
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		fmt.Println("status", resp.StatusCode, strings.TrimSpace(string(b)))
		if resp.StatusCode != http.StatusOK {
			os.Exit(3)
		}
	case len(a) >= 4 && a[0] == "serve":
		serve(a[1], strings.Split(a[2], ","), a[3:])
	case len(a) == 3 && a[0] == "ra":
		if err := ra(a[1], a[2]); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatal("usage: probe resolve SOCK HOST:PORT | dial SOCK HOST:PORT | get SOCK URL CA | serve DIR NAMES ADDR... | ra IFACE PREFIX")
	}
}

// fail prints rootd's refusal, the dial's failure, or the error, and exits 3.
func fail(err error, start time.Time) {
	var rf *resolve.Refused
	var de *dial.Error
	switch {
	case errors.As(err, &rf):
		fmt.Println("refused", rf.Reason)
	case errors.As(err, &de):
		fmt.Println("failed", de.What, time.Since(start).Milliseconds())
	case errors.Is(err, dial.ErrRedirect):
		fmt.Println("redirect")
	default:
		fmt.Println("error", err)
	}
	os.Exit(3)
}

func serve(dir string, names, addrs []string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "dial-gate"}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		log.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	for _, addr := range addrs {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatal(err)
		}
		srv := &http.Server{TLSConfig: cfg, ConnState: func(c net.Conn, s http.ConnState) {
			if s == http.StateNew {
				fmt.Println("accept", c.LocalAddr())
			}
		}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			local := r.Context().Value(http.LocalAddrContextKey)
			fmt.Printf("get %s sni=%s host=%s\n", local, r.TLS.ServerName, r.Host)
			if r.URL.Path == "/moved" {
				http.Redirect(w, r, "https://moved.dial.test/", http.StatusFound)
				return
			}
			fmt.Fprintf(w, "pinned %s\n", local)
		})}
		go func() { log.Fatal(srv.ServeTLS(ln, "", "")) }()
	}
	select {}
}

func ra(iface, prefix string) error {
	p, err := netip.ParsePrefix(prefix)
	if err != nil || !p.Addr().Is6() || p.Bits() != 64 {
		return fmt.Errorf("prefix %s: want an IPv6 /64", prefix)
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_ICMPV6)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	// a receiver drops an RA with any other hop limit; the kernel fills in the ICMPv6 checksum
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_HOPS, 255); err != nil {
		return err
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_IF, ifi.Index); err != nil {
		return err
	}
	// type 134, code 0, checksum, hop limit 64, flags 0, router lifetime 0, reachable time 0, retransmit timer 0
	msg := make([]byte, 16)
	msg[0], msg[4] = 134, 64
	// prefix information: type 3, length 4 (32 bytes), /64, on-link and autonomous, valid 3600 s, preferred 1800 s
	msg = append(msg, 3, 4, 64, 0xc0)
	msg = binary.BigEndian.AppendUint32(msg, 3600)
	msg = binary.BigEndian.AppendUint32(msg, 1800)
	msg = append(append(msg, 0, 0, 0, 0), p.Addr().AsSlice()...)
	to := &unix.SockaddrInet6{ZoneId: uint32(ifi.Index), Addr: netip.MustParseAddr("ff02::1").As16()}
	return unix.Sendto(fd, msg, 0, to)
}
