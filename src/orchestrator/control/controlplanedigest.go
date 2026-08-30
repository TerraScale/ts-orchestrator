package control

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
)

// invalidArgument stands in for C# ArgumentException / ArgumentNullException
// throws in ports where the caller distinguishes the failure.
func invalidArgument(message string) error {
	return errors.New(message)
}

func argumentNil(name string) error {
	return errors.New("Value cannot be null. (Parameter '" + name + "')")
}

const int64max = int64(^uint64(0) >> 1)

// isNullOrWhiteSpace mirrors string.IsNullOrWhiteSpace.
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

// derefString mirrors `value ?? null` for nullable strings.
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

// checkedAddInt64 mirrors C# checked arithmetic.
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
// the primitive value encodings below are shared, and they reproduce the C#
// writers byte-for-byte so journals stay readable across the migration.
//
// Encodings (mirroring the C# Append switch):
//   null      -> "N;"
//   string    -> "S" <utf16 length> ":" <text> ";"
//   bool      -> "B1;" / "B0;"
//   integer   -> "L" <invariant decimal> ";"
//   enum      -> integer form
//   timestamp -> "T" <utc .NET ticks> ";"
//   duration  -> "D" <.NET ticks> ";"
//   array     -> "A" <count> "[" <items> "];"

const dotNetEpochTicks = 621355968000000000 // 0001-01-01T00:00:00Z .. 1970-01-01T00:00:00Z

var (
	dotNetMinTimestamp = time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)
	dotNetMaxTimestamp = time.Date(9999, 12, 31, 23, 59, 59, 999999900, time.UTC)
)

// dotNetTimestampTicks returns .NET DateTimeOffset ticks (100ns units since
// 0001-01-01T00:00:00Z) for the instant of t.
func dotNetTimestampTicks(t time.Time) int64 {
	return t.Unix()*10000000 + int64(t.Nanosecond())/100 + dotNetEpochTicks
}

// dotNetDurationTicks returns .NET TimeSpan ticks (100ns units).
func dotNetDurationTicks(d time.Duration) int64 {
	return int64(d) / 100
}

// dotNetCanAdd mirrors DateTimeOffset addition overflow semantics: the sum
// must stay inside the DateTimeOffset range.
func dotNetCanAdd(timestamp time.Time, duration time.Duration) bool {
	sum := timestamp.Add(duration)
	return !sum.Before(dotNetMinTimestamp) && !sum.After(dotNetMaxTimestamp)
}

// dotNetTimeEquals compares two instants the way DateTimeOffset equality does.
func dotNetTimeEquals(left, right time.Time) bool {
	return left.Equal(right)
}

func digestUtf16Length(value string) int {
	isAscii := true
	for i := 0; i < len(value); i++ {
		if value[i] >= 0x80 {
			isAscii = false
			break
		}
	}
	if isAscii {
		return len(value)
	}
	return len(utf16.Encode([]rune(value)))
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
	w.builder.WriteString(itoaCompact(int64(digestUtf16Length(value))))
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
	w.builder.WriteString(itoaCompact(dotNetTimestampTicks(value)))
	w.builder.WriteByte(';')
}

func (w *digestWriter) WriteDuration(value time.Duration) {
	w.builder.WriteByte('D')
	w.builder.WriteString(itoaCompact(dotNetDurationTicks(value)))
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
	// strconv.FormatInt matches the C# invariant-culture formatting used by
	// the digest writers.
	return strconv.FormatInt(value, 10)
}
