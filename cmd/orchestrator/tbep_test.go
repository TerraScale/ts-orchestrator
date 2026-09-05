package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestObserveMemberDispatchWithoutControlConfiguration(t *testing.T) {
	for _, args := range [][]string{{"observe-member"}, {"observe-member", "--config"}, {"observe-member", "--config", ""}, {"observe-member", "--wrong", "secret"}, {"observe-member", "--config", "/missing/secret-config"}} {
		var output bytes.Buffer
		err := execute(context.Background(), args, func(string) (string, bool) { t.Fatal("observer consulted control-plane environment"); return "", false }, &output)
		if err == nil || !strings.Contains(err.Error(), "orchestrator observe-member:") || strings.Contains(err.Error(), "secret") || output.Len() != 0 {
			t.Fatalf("unsafe or successful missing config result: %v, %s", err, output.String())
		}
	}
}
