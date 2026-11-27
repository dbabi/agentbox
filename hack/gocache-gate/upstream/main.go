// Command upstream is hack/gocache-gate.sh's fake proxy.golang.org, run on the host: synthetic modules and a checksum
// database signed with a test key (internal/proxy/gocache/goproxytest), over TLS with a certificate a test CA signs.
// It listens on 127.0.0.1 only; vm.sh forwards that one port to the guest as 10.0.2.2 (AGENTBOX_VM_FWD). Under
// /_ctl/<token>/ the gate, as root on the box, alters, withdraws or slows files, forks the checksum database and reads
// the request log; the token never reaches a task. Test fixture: never shipped.
//
//	upstream -listen 127.0.0.1:7801 -token HEX -out DIR
//
// DIR gets ca.pem (the CA the gate's task image and proxy stand-in trust), vkey (the checksum database key) and
// fixture/ (a main module that imports the 64 modules of example.com/w, with go.mod, go.sum and a test).
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"agentbox/internal/proxy/gocache/goproxytest"
)

// Width is how many synthetic modules the warm-start fixture imports (A-G4: 60+).
const Width = 64

func main() {
	listen := flag.String("listen", "127.0.0.1:7801", "the TLS listener (loopback only)")
	token := flag.String("token", "", "the control path's secret, at least 16 hex digits")
	out := flag.String("out", "", "where ca.pem, vkey and fixture/ go")
	data := flag.Int("data", 96<<10, "bytes of incompressible data in each synthetic module")
	flag.Parse()
	if ap, err := netip.ParseAddrPort(*listen); err != nil || !ap.Addr().IsLoopback() {
		log.Fatalf("%s: must be a loopback address:port", *listen)
	}
	if *out == "" || len(*token) < 16 {
		log.Fatal("-out and a -token of 16 or more characters are required")
	}
	mods := modules(*data)
	up, err := goproxytest.New("sum.golang.org", mods)
	if err != nil {
		log.Fatal(err)
	}
	cert, caPEM, err := certs()
	if err != nil {
		log.Fatal(err)
	}
	if err := writeOut(*out, up, caPEM); err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", up)
	mux.Handle("/_ctl/"+*token+"/", http.StripPrefix("/_ctl/"+*token, control(up)))
	srv := &http.Server{Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}, ReadHeaderTimeout: 30 * time.Second}
	log.Printf("upstream: proxy.golang.org on %s, %d modules", *listen, len(mods))
	log.Fatal(srv.ServeTLS(ln, "", ""))
}

// modules: the warm-start set, example.com/w/m01..m64 at v1.0.0, each with incompressible data so a fill takes real
// bytes; example.com/m at three versions for go get and the takedown; a +incompatible and a pseudo-version.
func modules(data int) []goproxytest.Module {
	r := mrand.New(mrand.NewPCG(1, 2)) // the same bytes, so the same hashes, every run
	var mods []goproxytest.Module
	for i := 1; i <= Width; i++ {
		p := fmt.Sprintf("example.com/w/m%02d", i)
		b := make([]byte, data)
		for j := range b {
			b[j] = byte(r.Uint32())
		}
		mods = append(mods, goproxytest.Module{Path: p, Version: "v1.0.0", Files: map[string]string{
			"go.mod":   "module " + p + "\n\ngo 1.21\n",
			"m.go":     fmt.Sprintf("package m%02d\n\n// F is this module's number.\nfunc F() int { return %d }\n", i, i),
			"data.bin": string(b)}})
	}
	for _, v := range []string{"v1.0.0", "v1.1.0", "v1.2.0"} {
		mods = append(mods, goproxytest.Module{Path: "example.com/m", Version: v, Files: map[string]string{
			"go.mod": "module example.com/m\n\ngo 1.21\n", "m.go": "package m\n\n// V is the version.\nconst V = \"" + v + "\"\n"}})
	}
	mods = append(mods, goproxytest.Module{Path: "example.com/inc", Version: "v2.0.0+incompatible", Files: map[string]string{
		"inc.go": "package inc\n\n// V is the version.\nconst V = 2\n"}})
	mods = append(mods, goproxytest.Module{Path: "example.com/pseudo", Version: "v0.0.0-20260101000000-abcdefabcdef", Files: map[string]string{
		"go.mod": "module example.com/pseudo\n\ngo 1.21\n", "p.go": "package pseudo\n"}})
	return mods
}

// certs: a test CA, and a certificate it signs for proxy.golang.org and sum.golang.org.
func certs() (tls.Certificate, []byte, error) {
	ck, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "agentbox gocache gate CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &ck.PublicKey, ck)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "proxy.golang.org"},
		DNSNames: []string{"proxy.golang.org", "sum.golang.org", "localhost"}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour)}
	caCert, _ := x509.ParseCertificate(caDER)
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &sk.PublicKey, ck)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: sk}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), nil
}

func writeOut(dir string, up *goproxytest.Server, caPEM []byte) error {
	fx := filepath.Join(dir, "fixture")
	if err := os.MkdirAll(fx, 0o755); err != nil {
		return err
	}
	var req, imp, sum strings.Builder
	for i := 1; i <= Width; i++ {
		fmt.Fprintf(&req, "\texample.com/w/m%02d v1.0.0\n", i)
		fmt.Fprintf(&imp, "\t\"example.com/w/m%02d\"\n", i)
		fmt.Fprintf(&sum, "m%02d.F() + ", i)
	}
	var gs []string
	for _, l := range strings.Split(up.GoSum(), "\n") {
		if strings.HasPrefix(l, "example.com/w/") {
			gs = append(gs, l)
		}
	}
	files := map[string]string{
		filepath.Join(dir, "ca.pem"): string(caPEM),
		filepath.Join(dir, "vkey"):   up.VKey + "\n",
		filepath.Join(dir, "gosum"):  up.GoSum(),
		filepath.Join(fx, "go.mod"):  "module example.com/fx\n\ngo 1.21\n\nrequire (\n" + req.String() + ")\n",
		filepath.Join(fx, "go.sum"):  strings.Join(gs, "\n") + "\n",
		filepath.Join(fx, "fx.go"):   "package fx\n\nimport (\n" + imp.String() + ")\n\n// Sum adds every module's number.\nfunc Sum() int { return " + sum.String() + "0 }\n",
		filepath.Join(fx, "fx_test.go"): fmt.Sprintf("package fx\n\nimport \"testing\"\n\nfunc TestSum(t *testing.T) {\n\tif Sum() != %d {\n\t\tt.Fatal(Sum())\n\t}\n}\n",
			Width*(Width+1)/2),
	}
	for p, c := range files {
		if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// control is the gate's handle on the upstream: POST /alter, /gone, /slow, /fork; GET /log returns the request lines
// since the last read.
func control(up *goproxytest.Server) http.Handler {
	m := http.NewServeMux()
	on := func(r *http.Request) bool { return r.FormValue("on") == "1" }
	m.HandleFunc("POST /alter", func(w http.ResponseWriter, r *http.Request) {
		up.Alter(r.FormValue("mod"), r.FormValue("v"), r.FormValue("ext"), on(r))
	})
	m.HandleFunc("POST /gone", func(w http.ResponseWriter, r *http.Request) { up.Gone(r.FormValue("mod"), r.FormValue("v"), on(r)) })
	m.HandleFunc("POST /slow", func(w http.ResponseWriter, r *http.Request) {
		ms, _ := strconv.Atoi(r.FormValue("ms"))
		rate, _ := strconv.ParseInt(r.FormValue("rate"), 10, 64)
		up.Slow(time.Duration(ms)*time.Millisecond, rate)
	})
	m.HandleFunc("POST /fork", func(w http.ResponseWriter, r *http.Request) { up.Fork() })
	m.HandleFunc("GET /log", func(w http.ResponseWriter, r *http.Request) {
		for _, l := range up.Log() {
			fmt.Fprintln(w, l)
		}
	})
	return m
}
