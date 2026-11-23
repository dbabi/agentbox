package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type ent struct {
	name string
	typ  byte
	link string
}

func layer(es ...ent) []byte {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range es {
		tw.WriteHeader(&tar.Header{Name: e.name, Typeflag: e.typ, Linkname: e.link, Mode: 0o755})
	}
	tw.Close()
	return b.Bytes()
}

func dir(n string) ent      { return ent{n, tar.TypeDir, ""} }
func link(n, to string) ent { return ent{n, tar.TypeSymlink, to} }
func file(n string) ent     { return ent{n, tar.TypeReg, ""} }
func write(t *testing.T, b []byte) string {
	p := filepath.Join(t.TempDir(), "a.tar")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func code(err error) string {
	var r *Refused
	if errors.As(err, &r) {
		return r.Code
	}
	if err == nil {
		return ""
	}
	return "untyped: " + err.Error()
}

// untar and retar let a test rewrite one archive entry, as a crafted image would.
func untar(t *testing.T, b []byte) map[string][]byte {
	out := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(b))
	for {
		h, err := tr.Next()
		if err != nil {
			return out
		}
		var c bytes.Buffer
		c.ReadFrom(tr)
		out[h.Name] = c.Bytes()
	}
}

func blobPath(d string) string { return "blobs/sha256/" + strings.TrimPrefix(d, "sha256:") }

func digest(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }

// manifestOf and reseal let a test change the manifest and fix the index above it, so only the change under test is
// wrong.
func manifestOf(t *testing.T, fs map[string][]byte) (index, manifest) {
	var x index
	var m manifest
	if err := json.Unmarshal(fs["index.json"], &x); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(fs[blobPath(x.Manifests[0].Digest)], &m); err != nil {
		t.Fatal(err)
	}
	return x, m
}

func reseal(fs map[string][]byte, x index, m manifest) []byte {
	mb, _ := json.Marshal(m)
	delete(fs, blobPath(x.Manifests[0].Digest))
	fs[blobPath(digest(mb))] = mb
	x.Manifests[0].Digest, x.Manifests[0].Size = digest(mb), int64(len(mb))
	fs["index.json"], _ = json.Marshal(x)
	return Tar(fs)
}

var base = layer(dir("etc/"), dir("usr/"), dir("usr/bin/"), file("etc/hostname"), link("bin", "usr/bin"))

func TestBuildCheck(t *testing.T) {
	a := Build([][]byte{base}, Config{Architecture: "arm64", OS: "linux", Config: RunConfig{Env: []string{"PATH=/usr/bin"}, WorkingDir: "/usr/bin"}}, "localhost/x:1")
	if !bytes.Equal(a, Build([][]byte{base}, Config{Architecture: "arm64", OS: "linux", Config: RunConfig{Env: []string{"PATH=/usr/bin"}, WorkingDir: "/usr/bin"}}, "localhost/x:1")) {
		t.Fatal("Build is not reproducible")
	}
	img, err := Check(write(t, a))
	if err != nil {
		t.Fatal(err)
	}
	fs := untar(t, a)
	_, m := manifestOf(t, fs)
	if "sha256:"+img.ID != m.Config.Digest || img.Config.RootFS.DiffIDs[0] != digest(base) {
		t.Errorf("image %+v, manifest %+v", img, m)
	}
	// gzip layers are checked against their uncompressed diff_id
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	zw.Write(base)
	zw.Close()
	x, m := manifestOf(t, fs)
	delete(fs, blobPath(m.Layers[0].Digest))
	fs[blobPath(digest(z.Bytes()))] = z.Bytes()
	m.Layers[0] = descriptor{MediaType: layerGzip, Digest: digest(z.Bytes()), Size: int64(z.Len())}
	if _, err := Check(write(t, reseal(fs, x, m))); err != nil {
		t.Errorf("gzip layer: %v", err)
	}
}

// The #102 gate in a unit test: an archive whose index and manifest are the pinned ones but whose layer bytes, config
// or diff_id differ is refused, and so is every malformed layout.
func TestCheckRefusesCrafted(t *testing.T) {
	good := Build([][]byte{base}, Config{Architecture: "arm64", OS: "linux"}, "localhost/x:1")
	other := layer(dir("etc/"), file("etc/shadow"))
	cases := map[string]struct {
		edit func(fs map[string][]byte) []byte
		want string
	}{
		"same manifest, other layer bytes under the pinned name": {func(fs map[string][]byte) []byte {
			_, m := manifestOf(t, fs)
			fs[blobPath(m.Layers[0].Digest)] = other
			return Tar(fs)
		}, BlobMismatch},
		"same manifest, other config bytes under the pinned name": {func(fs map[string][]byte) []byte {
			_, m := manifestOf(t, fs)
			fs[blobPath(m.Config.Digest)] = []byte(`{"architecture":"arm64","os":"linux","config":{},"rootfs":{"type":"layers","diff_ids":["` + digest(other) + `"]}}`)
			return Tar(fs)
		}, BlobMismatch},
		"same index, other manifest bytes under the pinned name": {func(fs map[string][]byte) []byte {
			x, _ := manifestOf(t, fs)
			fs[blobPath(x.Manifests[0].Digest)] = []byte(`{"schemaVersion":2}`)
			return Tar(fs)
		}, BlobMismatch},
		"a consistent layer whose diff_id the config does not list": {func(fs map[string][]byte) []byte {
			x, m := manifestOf(t, fs)
			fs[blobPath(digest(other))] = other
			m.Layers[0] = descriptor{MediaType: layerTar, Digest: digest(other), Size: int64(len(other))}
			return reseal(fs, x, m)
		}, BlobMismatch},
		"a descriptor size that is not the blob's": {func(fs map[string][]byte) []byte {
			x, m := manifestOf(t, fs)
			m.Layers[0].Size++
			return reseal(fs, x, m)
		}, BlobMismatch},
		"a missing layer blob": {func(fs map[string][]byte) []byte {
			_, m := manifestOf(t, fs)
			delete(fs, blobPath(m.Layers[0].Digest))
			return Tar(fs)
		}, BlobMismatch},
		"two manifests in the index": {func(fs map[string][]byte) []byte {
			x, _ := manifestOf(t, fs)
			x.Manifests = append(x.Manifests, x.Manifests[0])
			fs["index.json"], _ = json.Marshal(x)
			return Tar(fs)
		}, BadArchive},
		"a nested index": {func(fs map[string][]byte) []byte {
			x, _ := manifestOf(t, fs)
			x.Manifests[0].MediaType = "application/vnd.oci.image.index.v1+json"
			fs["index.json"], _ = json.Marshal(x)
			return Tar(fs)
		}, BadArchive},
		"a zstd layer": {func(fs map[string][]byte) []byte {
			x, m := manifestOf(t, fs)
			m.Layers[0].MediaType = "application/vnd.oci.image.layer.v1.tar+zstd"
			return reseal(fs, x, m)
		}, BadArchive},
		"a stray entry": {func(fs map[string][]byte) []byte { fs["manifest.json"] = []byte("[]"); return Tar(fs) }, BadArchive},
		"data after index.json": {func(fs map[string][]byte) []byte {
			fs["index.json"] = append(fs["index.json"], "{}"...)
			return Tar(fs)
		}, BadArchive},
	}
	for name, c := range cases {
		if got := code(func() error { _, err := Check(write(t, c.edit(untar(t, good)))); return err }()); got != c.want {
			t.Errorf("%s: %s, want %s", name, got, c.want)
		}
	}
	// a repeated entry: podman would read one copy, the check the other
	var b bytes.Buffer
	b.Write(good[:len(good)-1024])
	tw := tar.NewWriter(&b)
	tw.WriteHeader(&tar.Header{Name: "index.json", Typeflag: tar.TypeReg, Size: 2, Mode: 0o644})
	tw.Write([]byte("{}"))
	tw.Close()
	if _, err := Check(write(t, b.Bytes())); code(err) != BadArchive {
		t.Errorf("repeated entry: %v", err)
	}
	if _, err := Check(write(t, good)); err != nil {
		t.Fatal(err)
	}
}

// The #109 gate in a unit test: each config a podman image can use against the host is refused with its own code, and
// a plain one passes.
func TestLint(t *testing.T) {
	for _, c := range []struct {
		rc   RunConfig
		want string
	}{
		{RunConfig{Env: []string{"PATH=/usr/bin", "HOME"}}, BadEnv},
		{RunConfig{Env: []string{"AWS_*=x"}}, BadEnv},
		{RunConfig{Env: []string{"*"}}, BadEnv},
		{RunConfig{Env: []string{"=x"}}, BadEnv},
		{RunConfig{Labels: map[string]string{"io.containers.autoupdate": "registry"}}, AutoUpdate},
		{RunConfig{Labels: map[string]string{"io.containers.autoupdate.authfile": "/root/auth.json"}}, AutoUpdate},
		{RunConfig{Labels: map[string]string{"io.podman.annotations.checkpoint.name": "x"}}, Checkpoint},
		{RunConfig{User: "0"}, User},
		{RunConfig{User: "agent"}, User},
		{RunConfig{WorkingDir: "work"}, Workdir},
		{RunConfig{Env: []string{"A=*", "B=", "PATH=/usr/bin"}, Labels: map[string]string{"org.opencontainers.image.version": "26.04"}, WorkingDir: "/workspace"}, ""},
	} {
		if got := code(Lint(c.rc)); got != c.want {
			t.Errorf("%+v: %q, want %q", c.rc, got, c.want)
		}
	}
	// a checkpoint annotation on the manifest or its index entry
	fs := untar(t, Build([][]byte{base}, Config{}, "localhost/x:1"))
	x, m := manifestOf(t, fs)
	m.Annotations = map[string]string{"io.podman.annotations.checkpoint.rootfsImageID": "x"}
	if _, err := Check(write(t, reseal(fs, x, m))); code(err) != Checkpoint {
		t.Errorf("manifest annotation: %v", err)
	}
	fs = untar(t, Build([][]byte{base}, Config{}, "localhost/x:1"))
	x, m = manifestOf(t, fs)
	x.Manifests[0].Annotations["io.podman.annotations.checkpoint.name"] = "x"
	if _, err := Check(write(t, reseal(fs, x, m))); code(err) != Checkpoint {
		t.Errorf("index annotation: %v", err)
	}
	if _, err := Check(write(t, Build([][]byte{base}, Config{Config: RunConfig{Env: []string{"HOME"}}}, "x"))); code(err) != BadEnv {
		t.Errorf("Check does not lint the config: %v", err)
	}
}

// WORKDIR is checked against the merged layers: a symlink anywhere on its path, in any layer, unless a later layer
// whites it out or makes its dir opaque.
func TestWorkdirSymlink(t *testing.T) {
	for _, c := range []struct {
		name   string
		layers [][]byte
		wd     string
		want   string
	}{
		{"the dir itself", [][]byte{layer(link("work", "/etc"))}, "/work", Workdir},
		{"a dir above it", [][]byte{layer(link("work", "/etc"))}, "/work/x/y", Workdir},
		{"through bin", [][]byte{base}, "/bin", Workdir},
		{"from a lower layer", [][]byte{layer(link("work", "/etc")), layer(file("etc/x"))}, "/work/x", Workdir},
		{"./-prefixed names", [][]byte{layer(link("./work", "/etc"))}, "/work", Workdir},
		{"replaced by a dir above", [][]byte{layer(link("work", "/etc")), layer(file(".wh.work"), dir("work/"))}, "/work", ""},
		{"an opaque parent", [][]byte{layer(dir("a/"), link("a/work", "/etc")), layer(dir("a/"), file("a/.wh..wh..opq"))}, "/a/work", ""},
		{"a symlink next to it", [][]byte{layer(dir("work/"), link("worker", "/etc"))}, "/work", ""},
		{"a link elsewhere", [][]byte{base}, "/usr/bin", ""},
		{"a symlink added in a later layer", [][]byte{layer(dir("work/")), layer(file(".wh.work"), link("work", "/etc"))}, "/work", Workdir},
	} {
		_, err := Check(write(t, Build(c.layers, Config{Config: RunConfig{WorkingDir: c.wd}}, "x")))
		if got := code(err); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestCheckRelease(t *testing.T) {
	d := t.TempDir()
	a := Build([][]byte{base}, Config{}, "x")
	p, sums := filepath.Join(d, "task.oci.tar"), filepath.Join(d, "SHA256SUMS")
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(p, a, 0o644))
	must(os.WriteFile(sums, Sums(map[string][]byte{"image/linux-arm64/task.oci.tar": a, "install.sh": []byte("x")}), 0o644))
	if err := CheckRelease(sums, "image/linux-arm64/task.oci.tar", p); err != nil {
		t.Fatal(err)
	}
	if err := CheckRelease(sums, "image/linux-amd64/task.oci.tar", p); code(err) != ReleaseSha256 {
		t.Errorf("unlisted name: %v", err)
	}
	must(os.WriteFile(p, append(a, 0), 0o644))
	if err := CheckRelease(sums, "image/linux-arm64/task.oci.tar", p); code(err) != ReleaseSha256 {
		t.Errorf("a changed file: %v", err)
	}
}
