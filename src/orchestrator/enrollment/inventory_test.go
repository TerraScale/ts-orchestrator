package enrollment

import (
	"context"
	"testing"
	"time"
)

func TestReserveRejectsUnscopedRecordsBeforeJournal(t *testing.T) {
	j := &Journal{}
	_, err := j.Reserve(context.Background(), Record{Region: "", Slot: 1, MemberID: "member", Generation: 1, OperationID: "op", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	if err != ErrInvalid {
		t.Fatalf("Reserve error = %v, want ErrInvalid", err)
	}
}

func TestReserveRejectsChangedRetryWithoutJournal(t *testing.T) {
	if err := validate(State{Records: map[string]Record{"gru:1": {Region: "gru", Slot: 1, MemberID: "", Generation: 1, OperationID: "op", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}}}); err != ErrInvalid {
		t.Fatalf("validate error = %v, want ErrInvalid", err)
	}
}
