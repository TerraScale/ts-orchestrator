package runmaterial

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"strings"
)

// ValidateReferences closes the supported run setting and JSON input-file
// references over one exact admitted inventory. File/Files and snake_case
// equivalents are the production declaration conventions; host_files contains
// inline future guest payloads, rather than local file references.
func ValidateReferences(settings map[string]string, files map[string][]byte) error {
	bad := errors.New("runmaterial: configuration references material outside signed inventory")
	require := func(path string) error {
		if path != "" && files[path] == nil {
			return bad
		}
		return nil
	}
	for key, value := range settings {
		if key == Environment {
			continue
		}
		if strings.HasSuffix(key, "_FILE") {
			if err := require(value); err != nil {
				return err
			}
		}
		if key == "TS_ORCH_COMMAND_TRUST_KEY_FILES" {
			for _, path := range strings.Split(value, ":") {
				if err := require(path); err != nil {
					return err
				}
			}
		}
	}
	var references func(any) error
	references = func(value any) error {
		switch v := value.(type) {
		case string:
			return require(v)
		case []any:
			for _, entry := range v {
				if err := references(entry); err != nil {
					return err
				}
			}
		case map[string]any:
			for _, entry := range v {
				if err := references(entry); err != nil {
					return err
				}
			}
		case nil:
			return nil
		default:
			return bad
		}
		return nil
	}
	var walk func(any) error
	walk = func(value any) error {
		switch v := value.(type) {
		case []any:
			for _, entry := range v {
				if err := walk(entry); err != nil {
					return err
				}
			}
		case map[string]any:
			for key, entry := range v {
				if key == "host_files" {
					continue
				}
				reference := strings.HasSuffix(key, "File") || strings.HasSuffix(key, "Files") || strings.HasSuffix(key, "_file") || strings.HasSuffix(key, "_files")
				if reference {
					if err := references(entry); err != nil {
						return err
					}
				} else if err := walk(entry); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, raw := range files {
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 || trimmed[0] != '{' && trimmed[0] != '[' {
			continue
		}
		var document any
		if json.Unmarshal(raw, &document) != nil {
			return bad
		}
		if err := walk(document); err != nil {
			return err
		}
	}
	return nil
}
