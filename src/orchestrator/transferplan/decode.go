package transferplan

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
)

func decodeInput(raw []byte, out *planInput) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var scan func(int) error
	scan = func(depth int) error {
		if depth > 32 {
			return errors.New("transfer plan: JSON nesting exceeds bound")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if token == nil {
			return errors.New("transfer plan: null input")
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("transfer plan: duplicate field")
				}
				seen[name] = true
				if err := scan(depth + 1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("transfer plan: malformed object")
			}
		case json.Delim('['):
			for decoder.More() {
				if err := scan(depth + 1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("transfer plan: malformed array")
			}
		}
		return nil
	}
	if err := scan(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("transfer plan: trailing JSON")
	}
	if err := knownFields(raw, reflect.TypeOf(*out)); err != nil {
		return err
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(out)
}

// encoding/json accepts case-insensitive aliases for struct fields. Admission
// accepts only the schema's exact JSON names, including nested component data.
func knownFields(raw []byte, typ reflect.Type) error {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if reflect.PointerTo(typ).Implements(reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()) {
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return err
		}
		allowed := map[string]reflect.Type{}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name != "" && name != "-" {
				allowed[name] = field.Type
			}
		}
		for name, value := range fields {
			field, ok := allowed[name]
			if !ok {
				return errors.New("transfer plan: unknown field")
			}
			if err := knownFields(value, field); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		var values []json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil {
			return err
		}
		for _, value := range values {
			if err := knownFields(value, typ.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}
