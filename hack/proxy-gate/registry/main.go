// Command registry is hack/proxy-gate.sh's fake package registry. It runs on the host, on 127.0.0.1 only; the test VM
// reaches it as 10.0.2.2:PORT through hack/vmnet, as release-serve and Tang. It serves HTTPS with a throwaway CA it
// makes at start, and synthetic packages only: npm (gate-app and its 24 dependencies, under /npm/), a PyPI simple index
// (gatepkg, under /simple/ and /files/), /hello, and /slow, which sends a byte every 500 ms for a minute. It logs every
// connection with its TLS server name, every request, and every close. The gate reads the log as root on the box at
// https://ctl.NAME/_log/TOKEN; that name's connections are not logged. Test fixture: never shipped.
//
//	registry -listen 127.0.0.1:7900 -name reg.gate.test -token T -ca FILE -log FILE
package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

// Deps is how many dependencies gate-app has: more than one per-task socket's 8 connections (§2.1), so npm's parallel
// fetches need more connections than that at once.
const Deps = 24

func main() {
	listen := flag.String("listen", "", "127.0.0.1:PORT")
	name := flag.String("name", "reg.gate.test", "the DNS name in the certificate and in every URL served")
	token := flag.String("token", "", "the secret path part of the log URL")
	caFile := flag.String("ca", "", "write the CA certificate (PEM) here")
	logFile := flag.String("log", "", "the connection and request log")
	flag.Parse()
	if ap, err := netip.ParseAddrPort(*listen); err != nil || !ap.Addr().IsLoopback() || len(*token) < 16 || *caFile == "" ||
		*logFile == "" || flag.NArg() > 0 {
		log.Fatal("usage: registry -listen 127.0.0.1:PORT [-name NAME] -token T (16+ chars) -ca FILE -log FILE (loopback only)")
	}
	lf, err := os.OpenFile(*logFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		log.Fatal(err)
	}
	r, caPEM, err := New(*name, *token, lf)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*caFile, caPEM, 0o644); err != nil {
		log.Fatal(err)
	}
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("serving https://%s/ on %s", *name, l.Addr())
	log.Fatal(r.Serve(l))
}

// Registry is the fake registry's state: its packages and its log.
type Registry struct {
	name, token string
	cert        tls.Certificate
	files       map[string][]byte // path -> body
	types       map[string]string // path -> content type
	mu          sync.Mutex
	logw        io.Writer
	log         bytes.Buffer
	ctl         map[string]bool // remote addresses of connections to ctl.<name>
}

// New makes a CA and a certificate for name and ctl.name, and the packages. It returns the CA certificate as PEM.
func New(name, token string, logw io.Writer) (*Registry, []byte, error) {
	r := &Registry{name: name, token: token, logw: logw, files: map[string][]byte{}, types: map[string]string{}, ctl: map[string]bool{}}
	caPEM, err := r.makeCert()
	if err != nil {
		return nil, nil, err
	}
	if err := r.makeNPM(); err != nil {
		return nil, nil, err
	}
	if err := r.makePyPI(); err != nil {
		return nil, nil, err
	}
	r.add("/hello", "text/plain", []byte("hello from the fake registry\n"))
	return r, caPEM, nil
}

func (r *Registry) add(path, ctype string, b []byte) { r.files[path], r.types[path] = b, ctype }

func (r *Registry) logf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	l := fmt.Appendf(nil, time.Now().UTC().Format("15:04:05.000")+" "+format+"\n", args...)
	r.log.Write(l)
	r.logw.Write(l)
}

func (r *Registry) makeCert() ([]byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "agentbox proxy-gate test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	ca, _ = x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: r.name},
		DNSNames: []string{r.name, "ctl." + r.name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	r.cert = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), nil
}

// tgz is an npm tarball: package/package.json and package/index.js.
func tgz(pkg map[string]any) ([]byte, error) {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	pj, _ := json.Marshal(pkg)
	for _, f := range []struct {
		name string
		body []byte
	}{{"package/package.json", pj}, {"package/index.js", fmt.Appendf(nil, "module.exports = %q;\n", pkg["name"])}} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body)), ModTime: time.Unix(1700000000, 0)}); err != nil {
			return nil, err
		}
		tw.Write(f.body)
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// makeNPM serves gate-app, which depends on gate-dep-01 to gate-dep-NN, each at 1.0.0, as packuments and tarballs.
func (r *Registry) makeNPM() error {
	app := map[string]any{"name": "gate-app", "version": "1.0.0", "dependencies": map[string]string{}}
	pkgs := []map[string]any{app}
	for i := 1; i <= Deps; i++ {
		n := fmt.Sprintf("gate-dep-%02d", i)
		app["dependencies"].(map[string]string)[n] = "1.0.0"
		pkgs = append(pkgs, map[string]any{"name": n, "version": "1.0.0"})
	}
	for _, p := range pkgs {
		n := p["name"].(string)
		t, err := tgz(p)
		if err != nil {
			return err
		}
		s512, s1 := sha512.Sum512(t), sha1.Sum(t)
		v := map[string]any{"name": n, "version": "1.0.0", "dist": map[string]any{
			"tarball":   "https://" + r.name + "/npm/" + n + "/-/" + n + "-1.0.0.tgz",
			"integrity": "sha512-" + base64.StdEncoding.EncodeToString(s512[:]), "shasum": hex.EncodeToString(s1[:])}}
		if d, ok := p["dependencies"]; ok {
			v["dependencies"] = d
		}
		doc, _ := json.Marshal(map[string]any{"name": n, "dist-tags": map[string]string{"latest": "1.0.0"},
			"versions": map[string]any{"1.0.0": v}})
		r.add("/npm/"+n, "application/json", doc)
		r.add("/npm/"+n+"/-/"+n+"-1.0.0.tgz", "application/octet-stream", t)
	}
	return nil
}

// makePyPI serves gatepkg 1.0.0 as a wheel behind a PEP 503 simple index whose link carries the wheel's sha256.
func (r *Registry) makePyPI() error {
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	files := []struct{ name, body string }{
		{"gatepkg/__init__.py", "NAME = \"gatepkg\"\n"},
		{"gatepkg-1.0.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: gatepkg\nVersion: 1.0.0\n"},
		{"gatepkg-1.0.0.dist-info/WHEEL", "Wheel-Version: 1.0\nGenerator: agentbox-proxy-gate\nRoot-Is-Purelib: true\nTag: py3-none-any\n"},
	}
	var record strings.Builder
	for _, f := range files {
		w, err := zw.Create(f.name)
		if err != nil {
			return err
		}
		io.WriteString(w, f.body)
		h := sha256.Sum256([]byte(f.body))
		fmt.Fprintf(&record, "%s,sha256=%s,%d\n", f.name, base64.RawURLEncoding.EncodeToString(h[:]), len(f.body))
	}
	record.WriteString("gatepkg-1.0.0.dist-info/RECORD,,\n")
	w, err := zw.Create("gatepkg-1.0.0.dist-info/RECORD")
	if err != nil {
		return err
	}
	io.WriteString(w, record.String())
	if err := zw.Close(); err != nil {
		return err
	}
	whl := "gatepkg-1.0.0-py3-none-any.whl"
	h := sha256.Sum256(b.Bytes())
	r.add("/files/"+whl, "application/octet-stream", b.Bytes())
	r.add("/simple/gatepkg/", "text/html", fmt.Appendf(nil, "<!DOCTYPE html>\n<html><body>\n<a href=\"/files/%s#sha256=%s\">%s</a>\n</body></html>\n",
		whl, hex.EncodeToString(h[:]), whl))
	return nil
}

func (r *Registry) isCtl(remote string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ctl[remote]
}

// Serve answers HTTPS on l until l fails.
func (r *Registry) Serve(l net.Listener) error {
	srv := &http.Server{
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ConnState: func(c net.Conn, s http.ConnState) {
			if s != http.StateClosed && s != http.StateHijacked {
				return
			}
			a := c.RemoteAddr().String()
			if r.isCtl(a) {
				r.mu.Lock()
				delete(r.ctl, a)
				r.mu.Unlock()
				return
			}
			r.logf("closed %s", a)
		},
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{r.cert}, MinVersion: tls.VersionTLS12,
			GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
				a := h.Conn.RemoteAddr().String()
				if h.ServerName == "ctl."+r.name {
					r.mu.Lock()
					r.ctl[a] = true
					r.mu.Unlock()
					return nil, nil
				}
				r.logf("conn %s sni=%s", a, h.ServerName)
				return nil, nil
			}},
	}
	return srv.ServeTLS(l, "", "")
}

// ServeHTTP serves the log on the ctl name, and otherwise the packages, /slow or 404, logging the request.
func (r *Registry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if r.isCtl(req.RemoteAddr) {
		if subtle.ConstantTimeCompare([]byte(req.URL.Path), []byte("/_log/"+r.token)) != 1 {
			http.NotFound(w, req)
			return
		}
		r.mu.Lock()
		b := bytes.Clone(r.log.Bytes())
		r.mu.Unlock()
		w.Write(b)
		return
	}
	status := http.StatusOK
	r.logf("req %s host=%s %s %s", req.RemoteAddr, req.Host, req.Method, req.URL.Path)
	defer func() { r.logf("done %s %s %d", req.RemoteAddr, req.URL.Path, status) }()
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		status = http.StatusMethodNotAllowed
		http.Error(w, "GET only", status)
		return
	}
	if req.URL.Path == "/slow" {
		w.Header().Set("Content-Type", "text/plain")
		f, _ := w.(http.Flusher)
		for range 120 {
			if _, err := io.WriteString(w, "."); err != nil {
				return
			}
			if f != nil {
				f.Flush()
			}
			select {
			case <-req.Context().Done():
				return
			case <-time.After(500 * time.Millisecond):
			}
		}
		return
	}
	b, ok := r.files[req.URL.Path]
	if !ok {
		status = http.StatusNotFound
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Content-Type", r.types[req.URL.Path])
	w.Write(b)
}
