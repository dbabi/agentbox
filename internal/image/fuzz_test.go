package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

// Fuzz targets for the checks rootd runs on the release's task image before podman load (#270): the archive's tar,
// its index, manifest, config and layers, and the release's SHA256SUMS.

// refused reports whether err is a refusal, and fails t on an untyped error: rootd's reply names the code.
func refused(t *testing.T, err error) bool {
	var r *Refused
	if err != nil && !errors.As(err, &r) {
		t.Fatalf("untyped error: %v", err)
	}
	return err != nil
}

// put writes b to name in dir and returns its path. The inputs of one fuzz process take turns on the files of one dir:
// a temp dir per input made file I/O most of a run.
func put(t *testing.T, dir, name string, b []byte) string {
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// FuzzCheck checks raw archive bytes: the outer tar's headers and entry names, and index.json.
func FuzzCheck(f *testing.F) {
	a := Build([][]byte{base, layer(dir("work/"), file("work/x"))}, Config{Config: RunConfig{WorkingDir: "/work"}}, "localhost/x:1")
	f.Add(a)
	// the same entries under ./ names, after dir entries for blobs/ and blobs/sha256/
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: "./blobs/", Mode: 0o755})
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: "./blobs/sha256/", Mode: 0o755})
	for tr := tar.NewReader(bytes.NewReader(a)); ; {
		h, err := tr.Next()
		if err != nil {
			break
		}
		h.Name = "./" + h.Name
		tw.WriteHeader(h)
		io.Copy(tw, tr)
	}
	tw.Close()
	f.Add(b.Bytes())
	tmp := f.TempDir()
	f.Fuzz(func(t *testing.T, b []byte) {
		_, err := Check(put(t, tmp, "a.tar", b))
		refused(t, err)
	})
}

// FuzzCheckParts checks an archive built from its parts, so a mutation reaches the parsers past the digests. In ix, m
// and c, @m, @c, @0 and @1 stand for the digest and size of the manifest, the config and each layer, and @d0 and @d1
// for each layer's diff_id. A layer is one entry a line: its typeflag byte, its name, then a space and its link
// target; gz gzips both layers. A passing image must have no link on WORKDIR's path that no whiteout could remove.
func FuzzCheckParts(f *testing.F) {
	add := func(cfg string, gz bool, l0, l1 string) {
		lt := layerTar
		if gz {
			lt = layerGzip
		}
		f.Add([]byte(`{"schemaVersion":2,"manifests":[{"mediaType":"`+manifestType+`",@m,"annotations":{"`+refName+`":"x"}}]}`),
			[]byte(`{"schemaVersion":2,"mediaType":"`+manifestType+`","config":{"mediaType":"`+configType+`",@c},"layers":[{"mediaType":"`+lt+`",@0},{"mediaType":"`+lt+`",@1}]}`),
			[]byte(`{"architecture":"arm64","os":"linux","config":`+cfg+`,"rootfs":{"type":"layers","diff_ids":[@d0,@d1]}}`), l0, l1, gz)
	}
	add(`{"Env":["PATH=/usr/bin"],"WorkingDir":"/usr/bin"}`, false, "5etc/\n5usr/\n5usr/bin/\n0etc/hostname\n2bin usr/bin", "5work/\n0work/x")
	add(`{"WorkingDir":"/work"}`, true, "2work /etc", "0.wh.work\n5work/")
	add(`{"WorkingDir":"/a/work"}`, false, "5a/\n2a/work /etc", "5a/\n0a/.wh..wh..opq")
	add(`{"WorkingDir":"/w/x"}`, false, "5w/\n2s /w", "2s/x /etc\n2evil /etc\n1h evil")
	add(`{"WorkingDir":"/work/x"}`, false, "2work /etc", "0etc/x")
	add(`{"User":"0","Labels":{"io.containers.autoupdate":"registry"}}`, false, "5etc/", "")
	tmp := f.TempDir()
	f.Fuzz(func(t *testing.T, ix, m, c []byte, l0, l1 string, gz bool) {
		desc := func(b []byte) []byte { return fmt.Appendf(nil, `"digest":%q,"size":%d`, digest(b), len(b)) }
		fs := map[string][]byte{"oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`)}
		var raw [2][]byte
		for i, s := range []string{l0, l1} {
			var es []ent
			for _, l := range strings.Split(s, "\n") {
				if l != "" {
					n, to, _ := strings.Cut(l[1:], " ")
					es = append(es, ent{n, l[0], to})
				}
			}
			raw[i] = layer(es...)
			b := raw[i]
			if gz {
				var z bytes.Buffer
				zw := gzip.NewWriter(&z)
				zw.Write(b)
				zw.Close()
				b = z.Bytes()
			}
			fs[blobPath(digest(b))] = b
			c = bytes.ReplaceAll(c, fmt.Appendf(nil, "@d%d", i), fmt.Appendf(nil, "%q", digest(raw[i])))
			m = bytes.ReplaceAll(m, fmt.Appendf(nil, "@%d", i), desc(b))
		}
		m = bytes.ReplaceAll(m, []byte("@c"), desc(c))
		fs[blobPath(digest(c))], fs[blobPath(digest(m))] = c, m
		fs["index.json"] = bytes.ReplaceAll(ix, []byte("@m"), desc(m))
		img, err := Check(put(t, tmp, "a.tar", Tar(fs)))
		if refused(t, err) {
			return
		}
		// what the layers leave on each path, in the order the config lists them; a layer with a whiteout, or one that
		// is not l0 or l1, may remove what is below it, so the paths known so far are forgotten
		known := map[string]byte{}
		for _, d := range img.Config.RootFS.DiffIDs {
			var l []byte
			for _, r := range raw {
				if digest(r) == d {
					l = r
				}
			}
			set, wh := map[string]byte{}, l == nil
			for tr := tar.NewReader(bytes.NewReader(l)); ; {
				h, err := tr.Next()
				if err != nil {
					break
				}
				if p := path.Clean("/" + h.Name); strings.HasPrefix(path.Base(p), ".wh.") {
					wh = true
				} else {
					set[p] = h.Typeflag
				}
			}
			if wh {
				clear(known)
			}
			maps.Copy(known, set)
		}
		for q := img.Config.Config.WorkingDir; q != "" && q != "/"; q = path.Dir(q) {
			if known[q] == tar.TypeSymlink || known[q] == tar.TypeLink {
				t.Fatalf("WORKDIR %q passed with a link at %q", img.Config.Config.WorkingDir, q)
			}
		}
	})
}

// FuzzCheckRelease: a file passes only if SHA256SUMS has the line "<its sha256>  <name>".
func FuzzCheckRelease(f *testing.F) {
	a := []byte("task image")
	f.Add(Sums(map[string][]byte{"image/linux-arm64/task.oci.tar": a, "install.sh": []byte("x")}), "image/linux-arm64/task.oci.tar", a)
	f.Add(Sums(map[string][]byte{"image/linux-arm64/task.oci.tar": a}), "image/linux-amd64/task.oci.tar", a)
	tmp := f.TempDir()
	f.Fuzz(func(t *testing.T, sums []byte, name string, b []byte) {
		if refused(t, CheckRelease(put(t, tmp, "SHA256SUMS", sums), name, put(t, tmp, "a", b))) {
			return
		}
		if line := "\n" + strings.TrimPrefix(digest(b), "sha256:") + "  " + name + "\n"; !strings.Contains("\n"+string(sums)+"\n", line) {
			t.Fatalf("passed: SHA256SUMS %q has no line %q", sums, line)
		}
	})
}
