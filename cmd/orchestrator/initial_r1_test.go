package main

import (
	"context"
	"io"
	"testing"
)

func TestInitialGRUR1Dispatch(t *testing.T) {
	for _, args := range [][]string{{"initial-gru-r1"}, {"initial-gru-r1", "--config"}, {"initial-gru-r1", "--config", ""}, {"initial-gru-r1", "--config", "/missing", "extra"}, {"initial-gru-r1", "--owner-key", "/missing"}} {
		if _, err := requestedCommand(args); err == nil {
			t.Fatalf("accepted %q", args)
		}
	}
	args := []string{"initial-gru-r1", "--config", "/missing-initial-r1-config"}
	if name, err := requestedCommand(args); err != nil || name != "initial-gru-r1" {
		t.Fatalf("dispatch: %s %v", name, err)
	}
	touched := false
	err := execute(context.Background(), args, func(string) (string, bool) { touched = true; return "", false }, io.Discard)
	if err == nil || touched {
		t.Fatalf("missing signed config did not fail before production composition: %v %v", err, touched)
	}
}
