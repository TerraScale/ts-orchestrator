package regionhost

import (
	"context"
	"errors"
	"testing"
)

func TestPollRetriesThenReturnsTheLastError(t *testing.T) {
	calls := 0
	err := poll(context.Background(), 0, 3, func() (bool, error) {
		calls++
		return false, errors.New("compartment not visible yet")
	})
	if calls != 3 || err == nil || err.Error() != "compartment not visible yet" {
		t.Fatalf("calls %d err %v", calls, err)
	}
	calls = 0
	if err := poll(context.Background(), 0, 9, func() (bool, error) { calls++; return calls == 2, nil }); err != nil || calls != 2 {
		t.Fatalf("calls %d err %v", calls, err)
	}
	if err := poll(context.Background(), 0, 1, func() (bool, error) { return false, nil }); err == nil {
		t.Fatal("a timeout returned no error")
	}
}
