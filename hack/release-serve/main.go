// Command release-serve serves a directory over plain HTTP on 127.0.0.1 only, for hack/gate.sh. The QEMU VM reaches
// it as http://10.0.2.2:PORT, a release URL that `agentbox seed` accepts only with --dev; firstboot still checks the
// seed's sha256 pin and the minisign signature. Each request is logged, so a gate can show what the VM fetched.
package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"strconv"
)

func main() {
	dir := flag.String("dir", "", "directory to serve")
	port := flag.Int("port", 0, "TCP port on 127.0.0.1")
	flag.Parse()
	if *dir == "" || *port < 1 || *port > 65535 || flag.NArg() > 0 {
		log.Fatal("usage: release-serve -dir DIR -port PORT")
	}
	l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(*port))) // loopback only, never all interfaces
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("serving %s on http://%s", *dir, l.Addr())
	files := http.FileServer(http.Dir(*dir))
	log.Fatal(http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL.Path)
		files.ServeHTTP(w, r)
	})))
}
