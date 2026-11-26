// Package gomodfilter is taskrun's Go module filter (ARCHITECTURE.md §6.2 "Go module cache"), the first GOPROXY entry
// on 127.0.0.1:8083 inside the container. go sends it every request, the unsigned @v/list, @latest and .info included,
// so it answers only exact canonical .info, .mod and .zip requests: it records the task's taint through the gate
// before it asks the proxy for anything, checks each version live at proxy.golang.org over TLS, and takes .mod and .zip
// from the proxy's /_cache/ path. Every other request gets the filter's own 404, and go asks proxy.golang.org over
// CONNECT instead, with TLS end to end.
//
// The grammar here is also the proxy's (internal/proxy/gocache): both sides check every request.
package gomodfilter

import (
	"net/http"
	"slices"
	"strings"

	"golang.org/x/mod/module"
)

// File is one module file a request names: the module path and canonical version, unescaped, and the extension
// (info, mod or zip).
type File struct {
	Path, Version, Ext string
}

// Key is the file's cache key (Appendix E): go:<module>@<version>.<ext>, unescaped.
func (f File) Key() string { return "go:" + f.Path + "@" + f.Version + "." + f.Ext }

// Escaped is the file's path below a GOPROXY root, built from the checked values, never from the request.
func (f File) Escaped() string {
	p, _ := module.EscapePath(f.Path)
	v, _ := module.EscapeVersion(f.Version)
	return "/" + p + "/@v/" + v + "." + f.Ext
}

// Request checks r against the §6.2 grammar both the filter and the proxy's cache path apply: an origin-form GET of
// <prefix>/<escaped module>/@v/<escaped version>.<ext>, ext one of exts, with no query string, no % in the raw path and
// no body. The module and version must unescape and pass module.Check, the version must be canonical (which keeps
// +incompatible), and the module must match none of the private patterns (GOPRIVATE syntax). A refusal reports its
// status: 405 for another method, 404 for anything else.
func Request(r *http.Request, prefix string, exts []string, private string) (File, int) {
	if r.Method != http.MethodGet {
		return File{}, http.StatusMethodNotAllowed
	}
	raw := r.RequestURI
	if !strings.HasPrefix(raw, prefix+"/") || strings.ContainsAny(raw, "%?#") || r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
		return File{}, http.StatusNotFound
	}
	f, ok := parse(raw[len(prefix):], exts)
	if !ok || (private != "" && module.MatchPrefixPatterns(private, f.Path)) {
		return File{}, http.StatusNotFound
	}
	return f, 0
}

// parse reads /<escaped module>/@v/<escaped version>.<ext>.
func parse(p string, exts []string) (File, bool) {
	mod, file, ok := strings.Cut(p[1:], "/@v/")
	if !ok || strings.Contains(file, "/") {
		return File{}, false
	}
	var f File
	for _, x := range exts {
		if v, ok := strings.CutSuffix(file, "."+x); ok {
			f.Ext, file = x, v
			break
		}
	}
	if f.Ext == "" || !slices.Contains(exts, f.Ext) {
		return File{}, false
	}
	var err error
	if f.Path, err = module.UnescapePath(mod); err != nil {
		return File{}, false
	}
	if f.Version, err = module.UnescapeVersion(file); err != nil {
		return File{}, false
	}
	if module.Check(f.Path, f.Version) != nil || module.CanonicalVersion(f.Version) != f.Version {
		return File{}, false
	}
	return f, true
}
