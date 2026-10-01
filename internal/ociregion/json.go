package ociregion

import (
	"bytes"
	"encoding/json/jsontext"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// jsonFloat retains the lexical distinction between a JSON integer and a JSON
// floating point amount. OCI billed GiB and receipt byte counts require integers.
type jsonFloat float64

func decodeJSON(wire []byte) (any, error) {
	decoder := jsontext.NewDecoder(bytes.NewReader(wire))
	value, err := decodeValue(decoder)
	if err != nil {
		return nil, err
	}
	if _, err = decoder.ReadToken(); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("extra JSON value")
		}
		return nil, err
	}
	return value, nil
}
func decodeValue(decoder *jsontext.Decoder) (any, error) {
	token, err := decoder.ReadToken()
	if err != nil {
		return nil, err
	}
	switch token.Kind() {
	case 'n':
		return nil, nil
	case 't':
		return true, nil
	case 'f':
		return false, nil
	case '"':
		return token.String(), nil
	case '0':
		s := token.String()
		if strings.ContainsAny(s, ".eE") {
			f, err := strconv.ParseFloat(s, 64)
			return jsonFloat(f), err
		}
		return strconv.ParseInt(s, 10, 64)
	case '{':
		m := Object{}
		for decoder.PeekKind() != '}' {
			key, err := decoder.ReadToken()
			if err != nil {
				return nil, err
			}
			if key.Kind() != '"' {
				return nil, fmt.Errorf("JSON object requires a field name")
			}
			name := key.String()
			if _, ok := m[name]; ok {
				return nil, fmt.Errorf("duplicate JSON field")
			}
			value, err := decodeValue(decoder)
			if err != nil {
				return nil, err
			}
			m[name] = value
		}
		_, err := decoder.ReadToken()
		return m, err
	case '[':
		a := []any{}
		for decoder.PeekKind() != ']' {
			value, err := decodeValue(decoder)
			if err != nil {
				return nil, err
			}
			a = append(a, value)
		}
		_, err := decoder.ReadToken()
		return a, err
	}
	return nil, fmt.Errorf("invalid JSON token")
}
