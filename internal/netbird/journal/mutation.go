// Package journal defines NetBird journal data; its values convey no authority.
package journal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"strings"
)

// MaxBodyBytes leaves room for base64 encoding in the protected 128KiB record.
const MaxBodyBytes = 64 << 10

var ErrMutation = errors.New("invalid NetBird journal mutation")

// Mutation preserves the exact request body, without any credential headers.
type Mutation struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Body   []byte `json:"body"`
}

func (Mutation) String() string     { return "NetBird journal mutation [redacted]" }
func (m Mutation) GoString() string { return m.String() }

func (m Mutation) Clone() Mutation {
	m.Body = bytes.Clone(m.Body)
	return m
}

// Freeze consumes the body before reservation. Later changes to the caller's
// request cannot change the fixed loopback request represented by the result.
func Freeze(request *http.Request) (Mutation, error) {
	if request == nil || request.Context().Err() != nil || request.URL == nil || request.URL.Scheme != "http" || request.URL.Host != "127.0.0.1:18081" ||
		request.URL.User != nil || request.URL.Opaque != "" || request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.ForceQuery ||
		request.URL.Fragment != "" || request.URL.RawFragment != "" || request.RequestURI != "" ||
		request.Host != "" && request.Host != "127.0.0.1:18081" || len(request.TransferEncoding) != 0 || request.ContentLength < -1 || request.ContentLength > MaxBodyBytes {
		return Mutation{}, ErrMutation
	}
	mutation := Mutation{Method: request.Method, Path: request.URL.Path}
	if !allowed(mutation.Method, mutation.Path) {
		return Mutation{}, ErrMutation
	}
	if request.Body != nil {
		body, err := io.ReadAll(io.LimitReader(request.Body, MaxBodyBytes+1))
		closeErr := request.Body.Close()
		if err != nil || closeErr != nil || len(body) > MaxBodyBytes {
			return Mutation{}, ErrMutation
		}
		mutation.Body = body
	}
	if request.Context().Err() != nil || request.ContentLength >= 0 && request.ContentLength != int64(len(mutation.Body)) {
		return Mutation{}, ErrMutation
	}
	if err := mutation.Validate(); err != nil {
		return Mutation{}, err
	}
	return mutation, nil
}

func (m Mutation) Validate() error {
	if !allowed(m.Method, m.Path) || len(m.Body) > MaxBodyBytes {
		return ErrMutation
	}
	if m.Method == http.MethodDelete {
		if len(m.Body) != 0 {
			return ErrMutation
		}
		return nil
	}
	var object map[string]any
	if json.Unmarshal(m.Body, &object) != nil || object == nil {
		return ErrMutation
	}
	return nil
}

// Digest binds exact bytes; it does not normalize or reinterpret JSON bodies.
func (m Mutation) Digest() (string, error) {
	if err := m.Validate(); err != nil {
		return "", err
	}
	wire, err := json.Marshal(m, json.Deterministic(true))
	if err != nil {
		return "", ErrMutation
	}
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:]), nil
}

func allowed(method, path string) bool {
	if len(path) > 512 {
		return false
	}
	parts := strings.Split(path, "/")
	if len(parts) < 3 || parts[0] != "" || parts[1] != "api" {
		return false
	}
	parts = parts[2:]
	if len(parts) == 1 {
		return method == http.MethodPost && (parts[0] == "groups" || parts[0] == "policies" || parts[0] == "setup-keys")
	}
	if len(parts) == 2 {
		if parts[0] == "dns" {
			return method == http.MethodPost && parts[1] == "zones" || method == http.MethodPut && parts[1] == "settings"
		}
		if !identifier(parts[1]) {
			return false
		}
		switch method {
		case http.MethodPut:
			return parts[0] == "groups" || parts[0] == "policies" || parts[0] == "accounts" || parts[0] == "peers" || parts[0] == "setup-keys"
		case http.MethodDelete:
			return parts[0] == "policies" || parts[0] == "peers"
		}
	}
	if len(parts) < 3 || parts[0] != "dns" || parts[1] != "zones" || !identifier(parts[2]) {
		return false
	}
	return len(parts) == 3 && method == http.MethodPut ||
		len(parts) == 4 && parts[3] == "records" && method == http.MethodPost ||
		len(parts) == 5 && parts[3] == "records" && identifier(parts[4]) && (method == http.MethodPut || method == http.MethodDelete)
}

func identifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_') {
			return false
		}
	}
	return true
}
