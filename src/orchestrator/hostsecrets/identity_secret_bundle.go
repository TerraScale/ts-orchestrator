package hostsecrets

import "bytes"

// Parse directly in locked response storage. JSON decoders materialize string
// values on the ordinary heap; this narrow parser instead retains bounded
// slices. OCI's identifiers, timestamps and base64 content need no escapes.
func identityBundleContent(body []byte, id string) ([]byte, error) {
	p := identityJSON{body: body, secretID: []byte(id)}
	if !p.value(nil, 0) || len(bytes.TrimSpace(p.body)) != 0 || !p.idOK || !p.versionOK || !p.typeOK || len(p.content) != 60 {
		return nil, ErrIdentitySecret
	}
	return p.content, nil
}

type identityJSON struct {
	body, secretID, content []byte
	idOK, versionOK, typeOK bool
}

func (p *identityJSON) space() { p.body = bytes.TrimSpace(p.body) }
func (p *identityJSON) quoted() ([]byte, bool) {
	p.space()
	if len(p.body) < 2 || p.body[0] != '"' {
		return nil, false
	}
	for n := 1; n < len(p.body); n++ {
		c := p.body[n]
		if c == '"' {
			s := p.body[1:n]
			p.body = p.body[n+1:]
			return s, true
		}
		if c < ' ' || c == '\\' {
			return nil, false
		}
	}
	return nil, false
}
func identityPath(path [][]byte, names ...string) bool {
	if len(path) != len(names) {
		return false
	}
	for n, name := range names {
		if !bytes.Equal(path[n], []byte(name)) {
			return false
		}
	}
	return true
}
func (p *identityJSON) value(path [][]byte, depth int) bool {
	p.space()
	if len(p.body) == 0 || depth > 16 {
		return false
	}
	switch p.body[0] {
	case '{':
		p.body = p.body[1:]
		p.space()
		if len(p.body) > 0 && p.body[0] == '}' {
			p.body = p.body[1:]
			return true
		}
		var names [][]byte
		for {
			name, ok := p.quoted()
			if !ok {
				return false
			}
			for _, seen := range names {
				if bytes.Equal(seen, name) {
					return false
				}
			}
			names = append(names, name)
			p.space()
			if len(p.body) == 0 || p.body[0] != ':' {
				return false
			}
			p.body = p.body[1:]
			if !p.value(append(path, name), depth+1) {
				return false
			}
			p.space()
			if len(p.body) == 0 {
				return false
			}
			c := p.body[0]
			p.body = p.body[1:]
			if c == '}' {
				return true
			}
			if c != ',' {
				return false
			}
		}
	case '[':
		p.body = p.body[1:]
		p.space()
		if len(p.body) > 0 && p.body[0] == ']' {
			p.body = p.body[1:]
			return true
		}
		for {
			if !p.value(append(path, []byte("[]")), depth+1) {
				return false
			}
			p.space()
			if len(p.body) == 0 {
				return false
			}
			c := p.body[0]
			p.body = p.body[1:]
			if c == ']' {
				return true
			}
			if c != ',' {
				return false
			}
		}
	case '"':
		v, ok := p.quoted()
		if !ok {
			return false
		}
		switch {
		case identityPath(path, "secretId"):
			p.idOK = bytes.Equal(v, p.secretID)
		case identityPath(path, "secretBundleContent", "contentType"):
			p.typeOK = bytes.Equal(v, []byte("BASE64"))
		case identityPath(path, "secretBundleContent", "content"):
			p.content = v
		case identityPath(path, "timeOfExpiry"), identityPath(path, "timeOfDeletion"):
			return false
		}
		return true
	default:
		n := 0
		for n < len(p.body) && p.body[n] != ',' && p.body[n] != ']' && p.body[n] != '}' && p.body[n] != ' ' && p.body[n] != '\n' && p.body[n] != '\r' && p.body[n] != '\t' {
			n++
		}
		if n == 0 {
			return false
		}
		v := p.body[:n]
		p.body = p.body[n:]
		if identityPath(path, "versionNumber") {
			p.versionOK = bytes.Equal(v, []byte("1"))
		}
		if identityPath(path, "timeOfExpiry") || identityPath(path, "timeOfDeletion") {
			return bytes.Equal(v, []byte("null"))
		}
		if bytes.Equal(v, []byte("true")) || bytes.Equal(v, []byte("false")) || bytes.Equal(v, []byte("null")) {
			return true
		}
		return identityJSONNumber(v)
	}
}
func identityJSONNumber(b []byte) bool {
	if len(b) > 0 && b[0] == '-' {
		b = b[1:]
	}
	if len(b) == 0 {
		return false
	}
	if b[0] == '0' {
		b = b[1:]
	} else {
		if b[0] < '1' || b[0] > '9' {
			return false
		}
		for len(b) > 0 && b[0] >= '0' && b[0] <= '9' {
			b = b[1:]
		}
	}
	if len(b) > 0 && b[0] == '.' {
		b = b[1:]
		n := len(b)
		for len(b) > 0 && b[0] >= '0' && b[0] <= '9' {
			b = b[1:]
		}
		if len(b) == n {
			return false
		}
	}
	if len(b) > 0 && (b[0] == 'e' || b[0] == 'E') {
		b = b[1:]
		if len(b) > 0 && (b[0] == '+' || b[0] == '-') {
			b = b[1:]
		}
		n := len(b)
		for len(b) > 0 && b[0] >= '0' && b[0] <= '9' {
			b = b[1:]
		}
		if len(b) == n {
			return false
		}
	}
	return len(b) == 0
}
