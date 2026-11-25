// Package image checks an OCI image archive before rootd hands it to `podman load` (issues #102 and #109): every blob
// against its own sha256, the manifest, config and layer graph, each layer's diff_id, and the config fields that let
// a podman image drive host behavior. A digest pin alone is not enough: GHSA-pggw-qqjf-6cxw (fixed in podman 5.8.10,
// not in Ubuntu's 5.7) let a crafted image match another image's digest with other layers and config.
package image

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Refusal codes, in the reply rootd's task.start gives and in its log.
const (
	ReleaseSha256  = "IMAGE_RELEASE_SHA256"   // the archive is not the bytes the signed release's SHA256SUMS names
	BadArchive     = "IMAGE_BAD_ARCHIVE"      // not a single-manifest OCI archive in the layout below
	BlobMismatch   = "IMAGE_BLOB_MISMATCH"    // a blob, size or diff_id differs from what the manifest or config says
	BadEnv         = "IMAGE_ENV"              // an Env entry with no '=' or a '*' in its name (CVE-2026-57231)
	AutoUpdate     = "IMAGE_AUTOUPDATE_LABEL" // io.containers.autoupdate* (CVE-2026-121885)
	Workdir        = "IMAGE_WORKDIR"          // a WORKDIR not a clean absolute path, or one that can resolve through a symlink (CVE-2026-55686)
	User           = "IMAGE_USER"             // a USER: tasks run --userns=keep-id, which podman 5.7 lets the image USER override
	Checkpoint     = "IMAGE_CHECKPOINT"       // a checkpoint annotation or label (CVE-2026-94603)
	maxJSON        = 1 << 20
	manifestType   = "application/vnd.oci.image.manifest.v1+json"
	configType     = "application/vnd.oci.image.config.v1+json"
	layerTar       = "application/vnd.oci.image.layer.v1.tar"
	layerGzip      = "application/vnd.oci.image.layer.v1.tar+gzip"
	refName        = "org.opencontainers.image.ref.name"
	checkpointKeys = "io.podman.annotations.checkpoint"
	autoUpdateKey  = "io.containers.autoupdate"
)

// Refused is a typed refusal: Code is one of the constants above.
type Refused struct{ Code, Detail string }

func (r *Refused) Error() string { return r.Code + ": " + r.Detail }

func refuse(code, f string, a ...any) error { return &Refused{code, fmt.Sprintf(f, a...)} }

// Config is the part of the OCI image config this package writes and reads.
type Config struct {
	Architecture string    `json:"architecture"`
	OS           string    `json:"os"`
	Config       RunConfig `json:"config"`
	RootFS       RootFS    `json:"rootfs"`
}

type RunConfig struct {
	User       string            `json:"User,omitempty"`
	Env        []string          `json:"Env,omitempty"`
	WorkingDir string            `json:"WorkingDir,omitempty"`
	Labels     map[string]string `json:"Labels,omitempty"`
}

type RootFS struct {
	Type    string   `json:"type"`
	DiffIDs []string `json:"diff_ids"`
}

type descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type manifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	Config        descriptor        `json:"config"`
	Layers        []descriptor      `json:"layers"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

type index struct {
	SchemaVersion int          `json:"schemaVersion"`
	Manifests     []descriptor `json:"manifests"`
}

// Image is a checked archive: ID is the image ID podman gives it (the config digest's hex), Manifest its manifest
// digest.
type Image struct {
	ID, Manifest string
	Config       Config
}

func digestOf(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }

// Build writes an OCI archive of uncompressed layers with config c (its rootfs is filled in), named ref. The same
// inputs give the same bytes, so a release can rebuild and pin it.
func Build(layers [][]byte, c Config, ref string) []byte {
	blobs := map[string][]byte{}
	put := func(b []byte) string { d := digestOf(b); blobs[d] = b; return d }
	c.RootFS = RootFS{Type: "layers"}
	var ld []descriptor
	for _, l := range layers {
		d := put(l)
		c.RootFS.DiffIDs = append(c.RootFS.DiffIDs, d)
		ld = append(ld, descriptor{MediaType: layerTar, Digest: d, Size: int64(len(l))})
	}
	cb, _ := json.Marshal(c)
	m, _ := json.Marshal(manifest{SchemaVersion: 2, MediaType: manifestType, Config: descriptor{MediaType: configType, Digest: put(cb), Size: int64(len(cb))}, Layers: ld})
	ix, _ := json.Marshal(index{SchemaVersion: 2, Manifests: []descriptor{{MediaType: manifestType, Digest: put(m), Size: int64(len(m)),
		Annotations: map[string]string{refName: ref}}}})
	files := map[string][]byte{"oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`), "index.json": ix}
	for d, b := range blobs {
		files["blobs/sha256/"+strings.TrimPrefix(d, "sha256:")] = b
	}
	return Tar(files)
}

// Tar writes files as a tar in name order, root-owned, with a fixed mtime.
func Tar(files map[string][]byte) []byte {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	mt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, n := range names {
		tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: n, Mode: 0o644, Size: int64(len(files[n])), ModTime: mt, Uname: "root", Gname: "root"})
		tw.Write(files[n])
	}
	tw.Close()
	return b.Bytes()
}

var blobName = regexp.MustCompile(`^blobs/sha256/[0-9a-f]{64}$`)

type blob struct {
	size  int64
	ok    bool   // its bytes hash to its name
	bytes []byte // kept for blobs up to maxJSON
}

// Check opens the archive at p and checks it, in order: the layout, every blob's sha256 and size, the
// manifest-config-layers graph, each layer's diff_id, then the config (Lint) and WORKDIR against the layers. It reads
// the file twice and keeps only the small blobs in memory.
func Check(p string) (Image, error) {
	var ix []byte
	blobs := map[string]*blob{}
	err := walk(p, func(name string, r io.Reader) error {
		switch {
		case name == "oci-layout":
			_, err := io.Copy(io.Discard, r)
			return err
		case name == "index.json":
			var err error
			ix, err = io.ReadAll(io.LimitReader(r, maxJSON+1))
			if err == nil && len(ix) > maxJSON {
				err = refuse(BadArchive, "index.json over %d bytes", maxJSON)
			}
			return err
		case blobName.MatchString(name):
			h := sha256.New()
			var keep bytes.Buffer
			n, err := io.Copy(io.MultiWriter(h, &capWriter{&keep, maxJSON}), r)
			if err != nil {
				return err
			}
			b := &blob{size: n, ok: hex.EncodeToString(h.Sum(nil)) == name[len("blobs/sha256/"):]}
			if n <= maxJSON {
				b.bytes = keep.Bytes()
			}
			blobs["sha256:"+name[len("blobs/sha256/"):]] = b
			return nil
		}
		return refuse(BadArchive, "unexpected entry %.80q", name)
	})
	if err != nil {
		return Image{}, err
	}
	var x index
	if err := strict(ix, &x); err != nil || x.SchemaVersion != 2 || len(x.Manifests) != 1 || x.Manifests[0].MediaType != manifestType {
		return Image{}, refuse(BadArchive, "index.json must name exactly one OCI image manifest (%v)", err)
	}
	if err := noCheckpoint(x.Manifests[0].Annotations); err != nil {
		return Image{}, err
	}
	mb, err := content(blobs, x.Manifests[0], true)
	if err != nil {
		return Image{}, err
	}
	var m manifest
	if err := strict(mb, &m); err != nil || m.SchemaVersion != 2 || m.MediaType != manifestType || m.Config.MediaType != configType || len(m.Layers) == 0 {
		return Image{}, refuse(BadArchive, "not an OCI image manifest with a config and layers (%v)", err)
	}
	if err := noCheckpoint(m.Annotations); err != nil {
		return Image{}, err
	}
	cb, err := content(blobs, m.Config, true)
	if err != nil {
		return Image{}, err
	}
	var c Config
	if err := strict(cb, &c); err != nil || c.RootFS.Type != "layers" || len(c.RootFS.DiffIDs) != len(m.Layers) {
		return Image{}, refuse(BadArchive, "the config's rootfs does not list one diff_id per layer (%v)", err)
	}
	for _, l := range m.Layers {
		if l.MediaType != layerTar && l.MediaType != layerGzip {
			return Image{}, refuse(BadArchive, "layer media type %.80q", l.MediaType)
		}
		if _, err := content(blobs, l, false); err != nil {
			return Image{}, err
		}
	}
	if err := Lint(c.Config); err != nil {
		return Image{}, err
	}
	wd := c.Config.WorkingDir // clean: Lint refused it otherwise
	// pass 2: each layer's diff_id, and what it does to WORKDIR and the dirs above it
	layers := map[string]*layerFacts{}
	err = walk(p, func(name string, r io.Reader) error {
		d := "sha256:" + strings.TrimPrefix(name, "blobs/sha256/")
		for _, l := range m.Layers {
			if l.Digest == d && layers[d] == nil {
				f, err := scanLayer(r, l.MediaType == layerGzip, wd)
				layers[d] = f
				return err
			}
		}
		_, err := io.Copy(io.Discard, r)
		return err
	})
	if err != nil {
		return Image{}, err
	}
	var fs map[string]byte // the merged type of WORKDIR and each dir above it: '2' a symlink, '1' a hard link, '5' a dir, '0' a file
	for i, l := range m.Layers {
		f := layers[l.Digest]
		if f == nil {
			return Image{}, refuse(BlobMismatch, "layer %d changed between the two reads", i)
		}
		if f.diffID != c.RootFS.DiffIDs[i] {
			return Image{}, refuse(BlobMismatch, "layer %d: diff_id %s, the config says %.80s", i, f.diffID, c.RootFS.DiffIDs[i])
		}
		if f.through != "" {
			return Image{}, refuse(Workdir, "layer %d writes %.80q below its own symlink or hard link, so it can put a symlink on WORKDIR %.80q", i, f.through, wd)
		}
		fs = f.apply(fs)
	}
	if wd != "" {
		for q := wd; q != "/"; q = path.Dir(q) {
			if t := fs[q]; t == tar.TypeSymlink || t == tar.TypeLink { // link(2) does not follow a symlink: a hard link can be one
				return Image{}, refuse(Workdir, "WORKDIR %.80q resolves through the symlink or hard link %.80q", wd, q)
			}
		}
	}
	return Image{ID: strings.TrimPrefix(m.Config.Digest, "sha256:"), Manifest: x.Manifests[0].Digest, Config: c}, nil
}

// Lint refuses the config fields that let an image drive host behavior through podman (#109). WORKDIR's symlinks
// need the layers, so Check tests those.
func Lint(c RunConfig) error {
	for _, e := range c.Env {
		k, _, ok := strings.Cut(e, "=")
		if !ok || k == "" || strings.Contains(k, "*") {
			return refuse(BadEnv, "Env entry %.80q: want NAME=value with no '*' in NAME", e)
		}
	}
	for k := range c.Labels {
		if k == autoUpdateKey || strings.HasPrefix(k, autoUpdateKey+".") {
			return refuse(AutoUpdate, "label %.80q", k)
		}
	}
	if err := noCheckpoint(c.Labels); err != nil {
		return err
	}
	if c.User != "" {
		return refuse(User, "USER %.80q: tasks run as the agent uid under keep-id", c.User)
	}
	// Check walks WORKDIR by its text, and the kernel follows a symlink before it applies '..'
	if c.WorkingDir != "" && (!path.IsAbs(c.WorkingDir) || path.Clean(c.WorkingDir) != c.WorkingDir) {
		return refuse(Workdir, "WORKDIR %.80q: want an absolute path with no '.', '..', '//' or trailing '/'", c.WorkingDir)
	}
	return nil
}

func noCheckpoint(m map[string]string) error {
	for k := range m {
		if strings.HasPrefix(k, checkpointKeys) {
			return refuse(Checkpoint, "%.80q", k)
		}
	}
	return nil
}

// content is the checked blob of d: present once, its bytes hashing to its name, of d's size.
func content(blobs map[string]*blob, d descriptor, small bool) ([]byte, error) {
	b := blobs[d.Digest]
	switch {
	case b == nil:
		return nil, refuse(BlobMismatch, "no blob %.80s", d.Digest)
	case !b.ok:
		return nil, refuse(BlobMismatch, "blob %.80s does not hash to its name", d.Digest)
	case b.size != d.Size:
		return nil, refuse(BlobMismatch, "blob %.80s is %d bytes, its descriptor says %d", d.Digest, b.size, d.Size)
	case small && b.bytes == nil:
		return nil, refuse(BadArchive, "blob %.80s over %d bytes", d.Digest, maxJSON)
	}
	return b.bytes, nil
}

// strict decodes one JSON value with nothing after it. It matches keys as podman's own encoding/json does, so both
// read the same Env, User, WorkingDir and Labels.
func strict(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.More() {
		return errors.New("data after the JSON value")
	}
	return nil
}

// walk calls f for each regular entry of the tar at p, refusing links, devices and a repeated name.
func walk(p string, f func(name string, r io.Reader) error) error {
	fh, err := os.Open(p)
	if err != nil {
		return err
	}
	defer fh.Close()
	seen := map[string]bool{}
	tr := tar.NewReader(bufio.NewReader(fh))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return refuse(BadArchive, "tar: %v", err)
		}
		n := strings.TrimPrefix(path.Clean(h.Name), "./")
		if h.Typeflag == tar.TypeDir && (n == "blobs" || n == "blobs/sha256") {
			continue
		}
		if h.Typeflag != tar.TypeReg || seen[n] {
			return refuse(BadArchive, "entry %.80q: want each a regular file, once", h.Name)
		}
		seen[n] = true
		if err := f(n, tr); err != nil {
			return err
		}
	}
}

// layerFacts is one layer's diff_id and what it does to WORKDIR's path: entries set a type, whiteouts delete, an
// opaque marker empties a dir of what the layers below put in it. through is an entry the layer writes below one of
// its own symlinks or hard links, if WORKDIR is set.
type layerFacts struct {
	diffID  string
	set     map[string]byte
	deleted []string
	opaque  []string
	through string
}

func scanLayer(r io.Reader, gz bool, wd string) (*layerFacts, error) {
	h := sha256.New()
	src := r
	if gz {
		z, err := gzip.NewReader(r)
		if err != nil {
			return nil, refuse(BlobMismatch, "layer gzip: %v", err)
		}
		src = z
	}
	f := &layerFacts{set: map[string]byte{}}
	links := map[string]bool{} // the layer's symlinks and hard links: a hard link can name a symlink
	tee := io.TeeReader(src, h)
	tr := tar.NewReader(tee)
	for {
		hd, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, refuse(BlobMismatch, "layer tar: %v", err)
		}
		p := path.Clean("/" + hd.Name)
		// The overlay driver (accounts.StorageConf) unpacks each layer into a dir of its own and follows that layer's
		// links on the way, so an entry below one lands where its name does not say. A build writes none there.
		// shortcut: this walk costs a name's length times its depth; bound names before app images (#173) come here.
		if wd != "" {
			for q := path.Dir(p); q != "/" && f.through == ""; q = path.Dir(q) {
				if links[q] {
					f.through = p
				}
			}
			if hd.Typeflag == tar.TypeSymlink || hd.Typeflag == tar.TypeLink {
				links[p] = true
			}
		}
		dir, base := path.Split(p)
		dir = path.Clean(dir)
		switch {
		case base == ".wh..wh..opq":
			f.opaque = append(f.opaque, dir)
		case strings.HasPrefix(base, ".wh."):
			f.deleted = append(f.deleted, path.Join(dir, base[len(".wh."):]))
		case on(p, wd):
			t := hd.Typeflag
			if t != tar.TypeSymlink && t != tar.TypeLink && t != tar.TypeDir {
				t = tar.TypeReg
			}
			f.set[p] = t
		}
	}
	if _, err := io.Copy(io.Discard, tee); err != nil { // the tar's padding counts toward the diff_id
		return nil, refuse(BlobMismatch, "layer: %v", err)
	}
	f.diffID = "sha256:" + hex.EncodeToString(h.Sum(nil))
	return f, nil
}

// on reports whether p is wd or a dir above it.
func on(p, wd string) bool { return p != "/" && (p == wd || strings.HasPrefix(wd, p+"/")) }

func (f *layerFacts) apply(fs map[string]byte) map[string]byte {
	out := map[string]byte{}
	gone := func(p string) bool {
		for _, d := range f.opaque {
			if strings.HasPrefix(p, d+"/") || d == "/" {
				return true
			}
		}
		for _, d := range f.deleted {
			if p == d || strings.HasPrefix(p, d+"/") {
				return true
			}
		}
		return false
	}
	for p, t := range fs {
		if !gone(p) {
			out[p] = t
		}
	}
	for p, t := range f.set {
		out[p] = t
	}
	return out
}

// capWriter keeps at most n bytes and drops the rest.
type capWriter struct {
	b *bytes.Buffer
	n int
}

func (w *capWriter) Write(p []byte) (int, error) {
	if room := w.n + 1 - w.b.Len(); room > 0 {
		w.b.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// CheckRelease checks that the file at p is the one the signed release's SHA256SUMS (sha256sum format) lists as name.
func CheckRelease(sums, name, p string) error {
	b, err := os.ReadFile(sums)
	if err != nil {
		return err
	}
	want := ""
	for _, l := range strings.Split(string(b), "\n") {
		if s, n, ok := strings.Cut(l, "  "); ok && n == name {
			want = s
		}
	}
	fh, err := os.Open(p)
	if err != nil {
		return err
	}
	defer fh.Close()
	h := sha256.New()
	if _, err := io.Copy(h, fh); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); want == "" || got != want {
		return refuse(ReleaseSha256, "%s is sha256 %s, the release's SHA256SUMS says %q for %s", p, got, want, name)
	}
	return nil
}

// Sums is SHA256SUMS for files, in sha256sum's format and name order.
func Sums(files map[string][]byte) []byte {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var b bytes.Buffer
	for _, n := range names {
		h := sha256.Sum256(files[n])
		fmt.Fprintf(&b, "%x  %s\n", h, n)
	}
	return b.Bytes()
}
