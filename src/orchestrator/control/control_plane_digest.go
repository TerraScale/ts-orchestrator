package control

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode"
)

func invalidArgument(message string) error {
	return errors.New(message)
}

func argumentNil(name string) error {
	return errors.New("Value cannot be null. (Parameter '" + name + "')")
}

func argumentOutOfRange(name string) error {
	return errors.New("Specified argument was out of the range of valid values. (Parameter '" + name + "')")
}

func argumentOutOfRangeError(name, message string) error {
	return errors.New(message + " (Parameter '" + name + "')")
}

func invalidOperation(message string) error {
	return errors.New(message)
}

const int64max = int64(^uint64(0) >> 1)

func isNullOrWhiteSpace(value string) bool {
	if value == "" {
		return true
	}
	for _, r := range value {
		if !isSpaceRune(r) {
			return false
		}
	}
	return true
}

func isSpaceRune(r rune) bool {
	switch r {
	case ' ', '\t', '\n', '\v', '\f', '\r', 0x85, 0xA0:
		return true
	}
	return unicode.IsSpace(r)
}

// derefString returns the empty string for a nil pointer.
func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func derefBool(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func maxInt64(left, right int64) int64 {
	if left > right {
		return left
	}
	return right
}

// checkedAddInt64 adds two int64s, reporting overflow instead of wrapping.
func checkedAddInt64(left, right int64) (int64, bool) {
	sum := left + right
	if (right > 0 && sum < left) || (right < 0 && sum > left) {
		return 0, false
	}
	return sum, true
}

// Shared primitive encodings for the control-plane journal digest
// canonicalizations (AuthorityDigest, OperationDigest, ...). Every digest
// class keeps its own typed Append switch next to the types it hashes; only
// the primitive value encodings below are shared.
//
// Encodings:
//
//	null      -> "N;"
//	string    -> "S" <v1 UTF-16 code-unit count> ":" <text> ";"
//	bool      -> "B1;" / "B0;"
//	integer   -> "L" <invariant decimal> ";"
//	enum      -> integer form
//	timestamp -> "T" <utc ticks, 100ns units since 0001-01-01T00:00:00Z> ";"
//	duration  -> "D" <ticks, 100ns units> ";"
//	array     -> "A" <count> "[" <items> "];"

const unixEpochOffsetTicks = 621355968000000000 // 0001-01-01T00:00:00Z .. 1970-01-01T00:00:00Z

var (
	minWireTimestamp = time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)
	maxWireTimestamp = time.Date(9999, 12, 31, 23, 59, 59, 999999900, time.UTC)
)

// timestampTicks returns ticks in 100ns units since
// 0001-01-01T00:00:00Z for the instant of t.
func timestampTicks(t time.Time) int64 {
	return t.Unix()*10000000 + int64(t.Nanosecond())/100 + unixEpochOffsetTicks
}

// durationTicks returns the duration in 100ns units.
func durationTicks(d time.Duration) int64 {
	return int64(d) / 100
}

// canAddDuration reports whether timestamp+duration stays inside the supported
// timestamp range (0001-01-01 through 9999-12-31).
func canAddDuration(timestamp time.Time, duration time.Duration) bool {
	sum := timestamp.Add(duration)
	return !sum.Before(minWireTimestamp) && !sum.After(maxWireTimestamp)
}

// instantsEqual compares two instants for point-in-time equality.
func instantsEqual(left, right time.Time) bool {
	return left.Equal(right)
}

// v1UTF16CodeUnitCount preserves the length field of persisted v1 material.
// Unicode scalar values outside the basic multilingual plane occupy two code
// units in that contract.
func v1UTF16CodeUnitCount(value string) int {
	count := 0
	for _, character := range value {
		count++
		if character > 0xFFFF {
			count++
		}
	}
	return count
}

type digestWriter struct {
	builder strings.Builder
}

func newDigestWriter() *digestWriter {
	return &digestWriter{}
}

func (w *digestWriter) WriteNull() {
	w.builder.WriteString("N;")
}

func (w *digestWriter) WriteString(value string) {
	w.builder.WriteByte('S')
	w.builder.WriteString(itoaCompact(int64(v1UTF16CodeUnitCount(value))))
	w.builder.WriteByte(':')
	w.builder.WriteString(value)
	w.builder.WriteByte(';')
}

func (w *digestWriter) WriteStringPointer(value *string) {
	if value == nil {
		w.WriteNull()
		return
	}
	w.WriteString(*value)
}

func (w *digestWriter) WriteBool(value bool) {
	if value {
		w.builder.WriteString("B1;")
		return
	}
	w.builder.WriteString("B0;")
}

func (w *digestWriter) WriteBoolPointer(value *bool) {
	if value == nil {
		w.WriteNull()
		return
	}
	w.WriteBool(*value)
}

func (w *digestWriter) WriteInt64(value int64) {
	w.builder.WriteByte('L')
	w.builder.WriteString(itoaCompact(value))
	w.builder.WriteByte(';')
}

func (w *digestWriter) WriteInt64Pointer(value *int64) {
	if value == nil {
		w.WriteNull()
		return
	}
	w.WriteInt64(*value)
}

func (w *digestWriter) WriteTime(value time.Time) {
	w.builder.WriteByte('T')
	w.builder.WriteString(itoaCompact(timestampTicks(value)))
	w.builder.WriteByte(';')
}

func (w *digestWriter) WriteDuration(value time.Duration) {
	w.builder.WriteByte('D')
	w.builder.WriteString(itoaCompact(durationTicks(value)))
	w.builder.WriteByte(';')
}

func (w *digestWriter) WriteArrayHeader(count int) {
	w.builder.WriteByte('A')
	w.builder.WriteString(itoaCompact(int64(count)))
	w.builder.WriteByte('[')
}

func (w *digestWriter) WriteArrayFooter() {
	w.builder.WriteString("];")
}

// WriteRaw splices an already-encoded fragment (a nested Encode result) into
// this writer.
func (w *digestWriter) WriteRaw(value string) {
	w.builder.WriteString(value)
}

func (w *digestWriter) Finish() string {
	return w.builder.String()
}

func digestHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func itoaCompact(value int64) string {
	// strconv.FormatInt renders plain invariant decimal digits, the form the
	// digest writers persist.
	return strconv.FormatInt(value, 10)
}
