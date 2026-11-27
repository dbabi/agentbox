package keys

import (
	"bytes"
	"encoding/json"
	"unicode/utf8"

	"agentbox/internal/ops"
)

// decodeJSON is one JSON value with numbers as json.Number, no repeated key at any depth and nothing after it: the
// vendor must parse the bytes keys checked as keys did.
func decodeJSON(b []byte) (any, error) { return ops.Decode(b) }

func utf8Valid(b []byte) bool { return utf8.Valid(b) }

// encodeJSON is v with no HTML escaping and no trailing newline.
func encodeJSON(v any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	e.Encode(v)
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}
