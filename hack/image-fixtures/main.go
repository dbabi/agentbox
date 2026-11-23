// Command image-fixtures writes the task image archives hack/image-gate.sh swaps in for the release's (issues #102 and
// #109): the release's own, one whose index and manifest are the release's but whose layer bytes differ, and one per
// config rootd refuses.
//
//	go run ./hack/image-fixtures -arch arm64 -out DIR
package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"agentbox/internal/image"
	"agentbox/internal/task"
)

func main() {
	arch := flag.String("arch", "arm64", "the box's architecture")
	out := flag.String("out", "", "output directory")
	flag.Parse()
	fx, err := fixtures(*arch)
	if err == nil {
		err = os.MkdirAll(*out, 0o755)
	}
	for name, b := range fx {
		if err == nil {
			err = os.WriteFile(filepath.Join(*out, name+".oci.tar"), b, 0o644)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "image-fixtures:", err)
		os.Exit(1)
	}
}

// want is the code rootd refuses each fixture with; "" loads.
var want = map[string]string{
	"good": "", "blob": image.BlobMismatch, "env": image.BadEnv, "autoupdate": image.AutoUpdate, "workdir": image.Workdir,
	"user": image.User, "checkpoint": image.Checkpoint,
}

func fixtures(arch string) (map[string][]byte, error) {
	sk := task.Skeleton()
	cfg := func(rc image.RunConfig) image.Config {
		return image.Config{Architecture: arch, OS: "linux", Config: rc}
	}
	var l bytes.Buffer
	tw := tar.NewWriter(&l)
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeSymlink, Name: "work", Linkname: "/etc", Mode: 0o777})
	tw.Close()
	good := task.Archive(arch)
	blob, err := swapLayer(good, append(append([]byte(nil), sk[:len(sk)-1024]...), entry("etc/shadow", "root::0:0:99999:7:::\n")...))
	return map[string][]byte{
		"good":       good,
		"blob":       blob,
		"env":        image.Build([][]byte{sk}, cfg(image.RunConfig{Env: []string{"PATH=/usr/bin", "HOME"}}), task.Image()),
		"autoupdate": image.Build([][]byte{sk}, cfg(image.RunConfig{Labels: map[string]string{"io.containers.autoupdate": "registry"}}), task.Image()),
		"workdir":    image.Build([][]byte{sk, l.Bytes()}, cfg(image.RunConfig{WorkingDir: "/work"}), task.Image()),
		"user":       image.Build([][]byte{sk}, cfg(image.RunConfig{User: "0"}), task.Image()),
		"checkpoint": image.Build([][]byte{sk}, cfg(image.RunConfig{Labels: map[string]string{"io.podman.annotations.checkpoint.name": "x"}}), task.Image()),
	}, err
}

// entry is one regular file as a tar stream, end marker included.
func entry(name, c string) []byte {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: int64(len(c))})
	tw.Write([]byte(c))
	tw.Close()
	return b.Bytes()
}

// swapLayer puts other bytes under the archive's one layer blob name, keeping its index, manifest and config: the
// crafted image of GHSA-pggw-qqjf-6cxw, which matches the pinned digests with other layers.
func swapLayer(a, layer []byte) ([]byte, error) {
	fs := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(a))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if fs[h.Name], err = io.ReadAll(tr); err != nil {
			return nil, err
		}
	}
	var x struct{ Manifests []struct{ Digest string } }
	var m struct{ Layers []struct{ Digest string } }
	if err := json.Unmarshal(fs["index.json"], &x); err != nil || len(x.Manifests) != 1 {
		return nil, fmt.Errorf("index.json: %v", err)
	}
	if err := json.Unmarshal(fs["blobs/sha256/"+strings.TrimPrefix(x.Manifests[0].Digest, "sha256:")], &m); err != nil || len(m.Layers) != 1 {
		return nil, fmt.Errorf("manifest: %v", err)
	}
	fs["blobs/sha256/"+strings.TrimPrefix(m.Layers[0].Digest, "sha256:")] = layer
	return image.Tar(fs), nil
}
