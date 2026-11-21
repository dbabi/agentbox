// Command preview serves site/web for a local look. It binds 127.0.0.1 only, on purpose, and has no host flag.
//
//	go run ./cmd/preview    # from site/tui, then open http://127.0.0.1:8080/
package main

import (
	"log"
	"net/http"
)

const addr = "127.0.0.1:8080" // loopback only: this is a preview, never a deploy

func main() {
	log.Printf("serving ../web on http://%s/ (ctrl+c stops)", addr)
	log.Fatal(http.ListenAndServe(addr, http.FileServer(http.Dir("../web"))))
}
