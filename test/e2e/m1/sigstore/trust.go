package sigstore

import (
	"bytes"
	"encoding/json"
	"fmt"
)

const trustedMarker = `"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1"`

func TrustBinary(binary, trusted []byte) ([]byte, error) {
	var formatted bytes.Buffer
	if err := json.Indent(&formatted, trusted, "", "  "); err != nil {
		return nil, err
	}
	trusted = formatted.Bytes()
	out := bytes.Clone(binary)
	patched := 0
	for offset := 0; ; {
		found := bytes.Index(out[offset:], []byte(trustedMarker))
		if found < 0 {
			break
		}
		start := bytes.LastIndexByte(out[:offset+found], '{')
		if start < offset || len(bytes.TrimSpace(out[start+1:offset+found])) != 0 {
			offset += found + len(trustedMarker)
			continue
		}
		decoder := json.NewDecoder(bytes.NewReader(out[start:]))
		var root json.RawMessage
		if err := decoder.Decode(&root); err != nil {
			return nil, err
		}
		length := int(decoder.InputOffset())
		if len(trusted) > length {
			return nil, fmt.Errorf("the lane's trusted root (%d bytes) is larger than the embedded one (%d bytes)", len(trusted), length)
		}
		copy(out[start:], trusted)
		copy(out[start+len(trusted):start+length], bytes.Repeat([]byte(" "), length-len(trusted)))
		patched++
		offset = start + length
	}
	if patched == 0 {
		return nil, fmt.Errorf("the binary embeds no Sigstore trusted root")
	}
	return out, nil
}
