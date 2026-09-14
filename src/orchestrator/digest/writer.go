// Package digest encodes the stable material used by control-plane journal
// hashes.
package digest

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

const dotNetEpochTicks = 621355968000000000

var (
	dotNetMinTimestamp = time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)
	dotNetMaxTimestamp = time.Date(9999, 12, 31, 23, 59, 59, 999999900, time.UTC)
)

// Writer produces the version-one length-prefixed journal encoding.
type Writer struct {
	builder strings.Builder
}

func NewWriter() *Writer { return &Writer{} }

func (w *Writer) WriteNull() {
	w.builder.WriteString("N;")
}

func (w *Writer) WriteString(value string) {
	w.builder.WriteByte('S')
	w.builder.WriteString(strconv.FormatInt(int64(UTF16CodeUnitCount(value)), 10))
	w.builder.WriteByte(':')
	w.builder.WriteString(value)
	w.builder.WriteByte(';')
}

func (w *Writer) WriteStringPointer(value *string) {
	if value == nil {
		w.WriteNull()
		return
	}
	w.WriteString(*value)
}

func (w *Writer) WriteBool(value bool) {
	if value {
		w.builder.WriteString("B1;")
		return
	}
	w.builder.WriteString("B0;")
}

func (w *Writer) WriteBoolPointer(value *bool) {
	if value == nil {
		w.WriteNull()
		return
	}
	w.WriteBool(*value)
}

func (w *Writer) WriteInt64(value int64) {
	w.builder.WriteByte('L')
	w.builder.WriteString(strconv.FormatInt(value, 10))
	w.builder.WriteByte(';')
}

func (w *Writer) WriteInt64Pointer(value *int64) {
	if value == nil {
		w.WriteNull()
		return
	}
	w.WriteInt64(*value)
}

func (w *Writer) WriteTime(value time.Time) {
	w.builder.WriteByte('T')
	w.builder.WriteString(strconv.FormatInt(timestampTicks(value), 10))
	w.builder.WriteByte(';')
}

func (w *Writer) WriteDuration(value time.Duration) {
	w.builder.WriteByte('D')
	w.builder.WriteString(strconv.FormatInt(int64(value)/100, 10))
	w.builder.WriteByte(';')
}

func (w *Writer) WriteArrayHeader(count int) {
	w.builder.WriteByte('A')
	w.builder.WriteString(strconv.FormatInt(int64(count), 10))
	w.builder.WriteByte('[')
}

func (w *Writer) WriteArrayFooter() {
	w.builder.WriteString("];")
}

// WriteRaw adds an already encoded nested value.
func (w *Writer) WriteRaw(value string) {
	w.builder.WriteString(value)
}

func (w *Writer) Finish() string {
	return w.builder.String()
}

// Hash returns a lowercase SHA-256 hash of encoded material.
func Hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// CanAddTime reports whether adding duration stays within the persisted
// DateTimeOffset range.
func CanAddTime(timestamp time.Time, duration time.Duration) bool {
	sum := timestamp.Add(duration)
	return !sum.Before(dotNetMinTimestamp) && !sum.After(dotNetMaxTimestamp)
}

// TimeEqual compares timestamps by instant.
func TimeEqual(left, right time.Time) bool {
	return left.Equal(right)
}

// UTF16CodeUnitCount returns the length used by version-one persisted text.
func UTF16CodeUnitCount(value string) int {
	count := 0
	for _, character := range value {
		count++
		if character > 0xFFFF {
			count++
		}
	}
	return count
}

func timestampTicks(value time.Time) int64 {
	return value.Unix()*10000000 + int64(value.Nanosecond())/100 + dotNetEpochTicks
}
