package control

import (
	"errors"
	"strconv"
	"time"
	"unicode"

	"terrascale.tech/orchestrator/src/orchestrator/digest"
)

// invalidArgument stands in for C# ArgumentException / ArgumentNullException
// throws in ports where the caller distinguishes the failure.
func invalidArgument(message string) error {
	return errors.New(message)
}

func argumentNil(name string) error {
	return errors.New("Value cannot be null. (Parameter '" + name + "')")
}

// argumentOutOfRange stands in for C# ArgumentOutOfRangeException.
func argumentOutOfRange(name string) error {
	return errors.New("Specified argument was out of the range of valid values. (Parameter '" + name + "')")
}

// argumentOutOfRangeError carries the C# ArgumentOutOfRangeException message.
func argumentOutOfRangeError(name, message string) error {
	return errors.New(message + " (Parameter '" + name + "')")
}

// invalidOperation stands in for C# InvalidOperationException.
func invalidOperation(message string) error {
	return errors.New(message)
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
// the primitive value encodings below are shared.
//
// Encodings:
//
//	null      -> "N;"
//	string    -> "S" <v1 UTF-16 code-unit count> ":" <text> ";"
//	bool      -> "B1;" / "B0;"
//	integer   -> "L" <invariant decimal> ";"
//	enum      -> integer form
//	timestamp -> "T" <utc .NET ticks> ";"
//	duration  -> "D" <.NET ticks> ";"
//	array     -> "A" <count> "[" <items> "];"

// dotNetCanAdd mirrors DateTimeOffset addition overflow semantics: the sum
// must stay inside the DateTimeOffset range.
func dotNetCanAdd(timestamp time.Time, duration time.Duration) bool {
	return digest.CanAddTime(timestamp, duration)
}

// dotNetTimeEquals compares two instants the way DateTimeOffset equality does.
func dotNetTimeEquals(left, right time.Time) bool {
	return digest.TimeEqual(left, right)
}

// v1UTF16CodeUnitCount preserves the length field of persisted v1 material.
// Unicode scalar values outside the basic multilingual plane occupy two code
// units in that contract.
func v1UTF16CodeUnitCount(value string) int {
	return digest.UTF16CodeUnitCount(value)
}

type digestWriter = digest.Writer

func newDigestWriter() *digestWriter {
	return digest.NewWriter()
}

func digestHash(value string) string {
	return digest.Hash(value)
}

func itoaCompact(value int64) string {
	return strconv.FormatInt(value, 10)
}
