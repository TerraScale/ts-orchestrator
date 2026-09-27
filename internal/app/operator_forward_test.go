package app

import "testing"

func TestOperatorForwardFlagRejectsDuplicateAndMalformedEntries(t *testing.T) {
	var forwards operatorForwardFlags
	if err := forwards.Set("10.251.0.11:4222=127.0.0.1:14222"); err != nil {
		t.Fatal(err)
	}
	if got := forwards["10.251.0.11:4222"]; got != "127.0.0.1:14222" {
		t.Fatalf("forward target = %q", got)
	}
	for _, value := range []string{
		"10.251.0.11:4222=127.0.0.1:14223", "10.251.0.12:4222", "=127.0.0.1:14223",
		"10.251.0.12:4222=", "10.251.0.12:4222=127.0.0.1:14223=extra",
	} {
		if err := forwards.Set(value); err == nil {
			t.Fatalf("invalid forward flag %q accepted", value)
		}
	}
}
