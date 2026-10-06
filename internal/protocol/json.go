package protocol

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"unicode/utf8"
)

const DefaultMaxJSONBytes = 1 << 20

var (
	ErrJSONTooLarge = errors.New("protocol JSON exceeds the configured size limit")
	ErrInvalidJSON  = errors.New("protocol JSON is invalid")
)

// EncodeJSON emits deterministic JSON. Deterministic map ordering keeps a given Go
// value's wire representation stable; signed payloads are also compacted before
// their digest is calculated.
func EncodeJSON(value any) ([]byte, error) {
	encoded, err := json.Marshal(value, json.Deterministic(true))
	if err != nil {
		return nil, fmt.Errorf("encode protocol JSON: %w", err)
	}
	return encoded, nil
}

// DecodeStrict decodes one bounded JSON value, rejecting duplicate names, invalid
// UTF-8, and unknown struct members. The Go 1.27 JSON v2 decoder rejects duplicate
// object names and invalid UTF-8 by default; RejectUnknownMembers closes the
// remaining permissive struct-decoding path.
func DecodeStrict(data []byte, destination any, maxBytes int) error {
	return decode(data, destination, maxBytes, true)
}

// DecodeTolerant is DecodeStrict for records a newer binary may have written:
// it skips members this binary does not know, so binary N-1 reads N's records.
// Duplicate names, invalid UTF-8 and the size limit still fail. A record's
// schema version names its breaking changes, and its reader checks it; a new
// member needs a safe zero value, since an older writer drops it.
func DecodeTolerant(data []byte, destination any, maxBytes int) error {
	return decode(data, destination, maxBytes, false)
}

func decode(data []byte, destination any, maxBytes int, rejectUnknown bool) error {
	if maxBytes == 0 {
		maxBytes = DefaultMaxJSONBytes
	}
	if maxBytes < 0 {
		return fmt.Errorf("%w: negative byte limit", ErrInvalidJSON)
	}
	if len(data) > maxBytes {
		return ErrJSONTooLarge
	}
	if !utf8.Valid(data) {
		return fmt.Errorf("%w: invalid UTF-8", ErrInvalidJSON)
	}
	if err := json.Unmarshal(data, destination,
		json.RejectUnknownMembers(rejectUnknown),
		jsontext.AllowDuplicateNames(false),
	); err != nil {
		return fmt.Errorf("decode protocol JSON: %w", err)
	}
	return nil
}
