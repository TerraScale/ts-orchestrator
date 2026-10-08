package entityid

import (
	"strings"
	"sync"
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
	for _, invalid := range []string{"", strings.ToLower(first), "acct_" + first,
		"00000000-0000-4000-8000-000000000001", "00000000000000000000000000",
		"80000000000000000000000000", "01ARZ3NDEKTSV4RRFFQ69G5FAI"} {
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

func TestConcurrentGeneration(t *testing.T) {
	const count = 1000
	results := make(chan string, count)
	var workers sync.WaitGroup
	for range 10 {
		workers.Go(func() {
			for range count / 10 {
				results <- New()
			}
		})
	}
	workers.Wait()
	close(results)
	seen := make(map[string]bool, count)
	for id := range results {
		if !Valid(id) || seen[id] {
			t.Fatalf("invalid or duplicate concurrent ID: %s", id)
		}
		seen[id] = true
	}
}
