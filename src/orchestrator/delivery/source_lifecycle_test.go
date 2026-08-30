package delivery

import (
	"context"
	"strings"
	"testing"
)

func TestSourceClientRejectsNilContextAndHonorsClose(t *testing.T) {
	client := &SourceClient{}
	commit := strings.Repeat("a", 40)
	if _, err := client.Resolve(nil, commit); err == nil {
		t.Fatal("nil context must be rejected without panicking")
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := client.Resolve(context.Background(), commit); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("closed client must reject requests, got %v", err)
	}
	if _, err := client.ReadArchive(nil, ResolvedRevision{
		Repository: "owner/repo", Commit: commit, Tree: commit,
	}); err == nil {
		t.Fatal("nil context on archive must be rejected without panicking")
	}
}
