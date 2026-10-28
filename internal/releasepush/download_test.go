package releasepush

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fra 2026-10-28 20:11Z: a 60 s whole-download timeout failed the install
// under CPU load. A download that keeps arriving finishes; a stalled one ends.
func TestDownloadCancelsOnlyWhenStalled(t *testing.T) {
	defer func(before time.Duration) { downloadStall = before }(downloadStall)
	downloadStall = 250 * time.Millisecond
	pause := 10 * time.Millisecond
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for range 60 {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(pause):
			}
			w.Write([]byte("binary"))
			w.(http.Flusher).Flush()
		}
	}))
	defer srv.Close()
	h := &Handler{Client: srv.Client()}
	data, err := h.download(t.Context(), srv.URL)
	if err != nil || string(data) != strings.Repeat("binary", 60) {
		t.Fatalf("progressing download: %d bytes, %v", len(data), err)
	}
	pause = time.Second
	if _, err := h.download(t.Context(), srv.URL); !errors.Is(err, context.Canceled) {
		t.Fatalf("stalled download: %v, want canceled", err)
	}
}
