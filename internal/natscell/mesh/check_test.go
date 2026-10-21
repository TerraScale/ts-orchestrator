package mesh

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAnswers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("Name: run-1\nHostname: ts-sjc-1\n"))
	}))
	defer srv.Close()
	if err := answers(t.Context(), srv.URL, []string{"Name: run-1", "Hostname: ts-sjc-1"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if err := answers(ctx, srv.URL, []string{"Name: run-2"}); err == nil || !strings.Contains(err.Error(), "run-2") {
		t.Fatalf("wrong marker err = %v", err)
	}
}
