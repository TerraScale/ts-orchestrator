package entityid

import (
	"testing"
	"time"
)

func TestContract(t *testing.T) {
	at := time.Now().Truncate(time.Millisecond)
	first, second := NewAt(at), NewAt(at)
	if !Valid(first) || !Valid(second) || first >= second {
		t.Fatalf("same-millisecond IDs are not canonical and monotonic: %s, %s", first, second)
	}
	parsed, err := Parse(first)
	if err != nil || parsed.Time() != uint64(at.UnixMilli()) {
		t.Fatalf("record time lost: %v, %v", parsed, err)
	}
	for _, invalid := range []string{""} {
		if Valid(invalid) {
			t.Errorf("accepted invalid ID %q", invalid)
		}
	}
	derived := Derive("operation", first, "host")
	if !Valid(derived) || derived != Derive("operation", first, "host") ||
		derived == Derive("other", first, "host") || derived == Derive("operation", "host", first) {
		t.Fatal("derived operation identity lost validity, idempotence or scope")
	}
}
