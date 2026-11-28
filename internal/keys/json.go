package keys

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"unicode/utf8"

	"agentbox/internal/ops"
)

// MaxDepth and MaxValues cap a request body's JSON before keys builds its tree (#315): the tree costs tens of bytes a
// value whatever the body's size, and the checks recurse once a level. The recorded Claude Code and Codex requests
// nest 10 and 16 levels deep, in their tool schemas; a long session adds values, not levels.
const (
	MaxDepth  = 64
	MaxValues = 1 << 18
)

// decodeJSON is one JSON value with numbers as json.Number, no repeated key at any depth and nothing after it, within
// MaxDepth and MaxValues: the vendor must parse the bytes keys checked as keys did.
func decodeJSON(b []byte) (any, error) { return ops.DecodeLimited(b, MaxDepth, MaxValues) }

// decodeRej is the refusal of a body decodeJSON refused, at the body's root.
func decodeRej(err error) *rej {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ops.ErrTooDeep):
		return &rej{what: "field", ptr: "/", wording: fmt.Sprintf("the request body nests JSON deeper than %d levels", MaxDepth)}
	case errors.Is(err, ops.ErrTooMany):
		return &rej{what: "field", ptr: "/", wording: fmt.Sprintf("the request body holds more than %d JSON values", MaxValues)}
	}
	return &rej{what: "field", ptr: "/", wording: "the request body is not one JSON object with unique keys"}
}

func utf8Valid(b []byte) bool { return utf8.Valid(b) }

// encodeJSON is v with no HTML escaping and no trailing newline.
func encodeJSON(v any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	e.Encode(v)
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}
