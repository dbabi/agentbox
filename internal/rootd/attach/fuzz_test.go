package attach

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"testing"
)

// packObj is one object of a test pack: a blob (3), or an OFS_DELTA (6) or REF_DELTA (7) whose delta copies 4 base
// bytes, then inserts body in chunks of at most 127 bytes, as git cuts an insert.
type packObj struct {
	typ  byte
	body []byte
}

// packOf is a git pack, v2, of objs, for an object id of idLen bytes. inPack reads no trailer checksum.
func packOf(idLen int, objs ...packObj) []byte {
	b := bytes.NewBufferString("PACK")
	binary.Write(b, binary.BigEndian, [2]uint32{2, uint32(len(objs))})
	for _, o := range objs {
		data := o.body
		if o.typ >= 6 {
			data = binary.AppendUvarint(binary.AppendUvarint(nil, 4), uint64(4+len(o.body)))
			data = append(data, 0x90, 4) // copy 4 bytes from offset 0
			for rest := o.body; len(rest) > 0; rest = rest[min(len(rest), 127):] {
				data = append(append(data, byte(min(len(rest), 127))), rest[:min(len(rest), 127)]...)
			}
		}
		n := len(data)
		c := o.typ<<4 | byte(n&15)
		for n >>= 4; n > 0; n >>= 7 {
			b.WriteByte(c | 0x80)
			c = byte(n & 0x7f)
		}
		b.WriteByte(c)
		switch o.typ {
		case 6:
			b.WriteByte(1) // the base's offset back
		case 7:
			b.Write(make([]byte, idLen))
		}
		w := zlib.NewWriter(b)
		w.Write(data)
		w.Close()
	}
	b.Write(make([]byte, idLen))
	return b.Bytes()
}

// FuzzInPack: a session writes the packs that the post-attach scan reads in rootd, so inPack takes any bytes. It never
// panics, and in a pack it can parse, a token in a blob or in what a delta inserts is found, and only then.
func FuzzInPack(f *testing.F) {
	f.Add([]byte(nil), []byte(access))
	f.Add(packOf(20, packObj{3, []byte("x " + access)}), []byte("no token"))
	f.Add(packOf(32, packObj{3, []byte("base")}, packObj{6, bytes.Repeat([]byte(access), 9)}, packObj{7, []byte(access)}), []byte(access[:10]))
	m := newMatcher([]string{access})
	f.Fuzz(func(t *testing.T, raw, body []byte) {
		// shortcut: deflate inflates up to about 1000:1, so a longer input only runs slower; raise the bound once a
		// delta's inserts count against inPack's inflate budget (#224)
		if len(raw)+len(body) > 16<<10 {
			return
		}
		m.inPack(bytes.NewReader(raw), 20)
		m.inPack(bytes.NewReader(raw), 32)
		want := bytes.Contains(body, []byte(access))
		for _, typ := range []byte{3, 6, 7} {
			if got := m.inPack(bytes.NewReader(packOf(20, packObj{3, []byte("base")}, packObj{typ, body})), 20); got != want {
				t.Fatalf("type %d object %q: found %v", typ, body, got)
			}
		}
	})
}
