package rootfoundation

import (
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
)

func TestOriginalRequestHistoryCannotBeRewritten(t *testing.T) {
	now := time.Now().UTC()
	attempt := ociresource.RequestAttempt{Method: "PUT", URL: "https://iaas.example/owned", Body: []byte(`{"owned":true}`), RetryToken: "original", IfMatch: "etag", StartedAt: now, Deadline: now.Add(time.Minute)}
	previous := ociresource.Operation{Requests: []ociresource.RequestAttempt{attempt}}
	for _, field := range []string{"remove", "body", "token", "deadline", "target"} {
		t.Run(field, func(t *testing.T) {
			current := attempt
			next := ociresource.Operation{Requests: []ociresource.RequestAttempt{current}}
			switch field {
			case "remove":
				next.Requests = nil
			case "body":
				next.Requests[0].Body = []byte(`{"owned":false}`)
			case "token":
				next.Requests[0].RetryToken = "new"
			case "deadline":
				next.Requests[0].Deadline = now.Add(time.Hour)
			case "target":
				next.Requests[0].URL += "/other"
			}
			if err := originalRequests(previous, next); err == nil {
				t.Fatal("original request history was rewritten")
			}
		})
	}
	next := attempt
	next.Sent, next.Status, next.FinishedAt = true, 200, now.Add(time.Second)
	if err := originalRequests(previous, ociresource.Operation{Requests: []ociresource.RequestAttempt{next}}); err != nil {
		t.Fatal(err)
	}
}
