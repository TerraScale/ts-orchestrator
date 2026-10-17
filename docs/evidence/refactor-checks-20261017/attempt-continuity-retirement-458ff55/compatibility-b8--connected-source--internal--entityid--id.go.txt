// Package entityid owns TerraScale's plain, canonical ULID contract.
package entityid

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

var (
	entropy = ulid.Monotonic(rand.Reader, 0)
	mu      sync.Mutex
)

// New returns a cryptographically random ULID, monotonic within a millisecond.
func New() string { return NewAt(time.Now()) }

// NewAt stamps an ID with the record's time. The entropy reader is shared and
// serialized because the library's monotonic reader is not concurrency-safe.
func NewAt(at time.Time) string {
	mu.Lock()
	defer mu.Unlock()
	return ulid.MustNew(ulid.Timestamp(at), entropy).String()
}

// Parse accepts only nonzero, uppercase, 26-character Crockford ULIDs.
func Parse(value string) (ulid.ULID, error) {
	id, err := ulid.ParseStrict(value)
	if err != nil || id == (ulid.ULID{}) || id.String() != value {
		return ulid.ULID{}, errors.New("entity ID must be a canonical uppercase ULID")
	}
	return id, nil
}

func Valid(value string) bool {
	_, err := Parse(value)
	return err == nil
}

// Derive gives an idempotent operation a stable ULID. A zero timestamp marks
// derived identities as having no creation time; the 80 entropy bits bind the
// domain-separated input. New entities use New instead.
func Derive(domain string, values ...string) string {
	h := sha256.New()
	for _, value := range append([]string{domain}, values...) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		h.Write(size[:])
		h.Write([]byte(value))
	}
	return ulid.MustNew(0, bytes.NewReader(h.Sum(nil)[:10])).String()
}
