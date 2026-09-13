package dashboard

import (
	"bufio"
	"context"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestReadOnlyStateAndHealthEndpoints(t *testing.T) {
	store := NewStore(State{Runtime: Runtime{Cell: "test", Health: "healthy"}})
	handler := NewServer(store).Handler()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/state", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("state status = %d", response.Code)
	}
	var state State
	if err := json.Unmarshal(response.Body.Bytes(), &state); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if state.Runtime.Cell != "test" {
		t.Fatalf("unexpected state: %+v", state)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("health status = %d", response.Code)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/state", nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("mutation status = %d", response.Code)
	}
}

func TestMPARoutesRenderDistinctPages(t *testing.T) {
	handler := NewServer(NewStore(State{})).Handler()
	for path, page := range map[string]string{"/": "overview", "/regions": "regions", "/nodes": "nodes", "/events": "events", "/terrabase": "terrabase", "/delivery": "delivery"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `data-page="`+page+`"`) || strings.Contains(response.Body.String(), "<h1>Orchestrator state</h1>") {
			t.Fatalf("route %s did not render page %s: status=%d", path, page, response.Code)
		}
	}
}

func TestUnknownRoutesAndStateCaching(t *testing.T) {
	handler := NewServer(NewStore(State{})).Handler()
	for _, path := range []string{"/unknown", "/api/unknown", "/vendor/nope"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("unknown route %s status = %d", path, response.Code)
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/state", nil))
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("state cache policy = %q", got)
	}
}

func TestEventsStreamPublishesSnapshotChanges(t *testing.T) {
	store := NewStore(State{Runtime: Runtime{Cell: "test", Health: "healthy"}})
	server := httptest.NewServer(NewServer(store).Handler())
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/api/events", nil)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	lines := bufio.NewScanner(response.Body)
	if !lines.Scan() || lines.Text() != "event: state" {
		t.Fatalf("first event line = %q", lines.Text())
	}
	for lines.Scan() && !strings.HasPrefix(lines.Text(), "data: ") {
	}
	store.Set(State{Runtime: Runtime{Cell: "sfo", Health: "degraded"}, ObservedAt: time.Now().UTC()})
	readLines := make(chan string, 16)
	go func() {
		for lines.Scan() {
			readLines <- lines.Text()
		}
		close(readLines)
	}()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for state event")
		case line := <-readLines:
			if strings.Contains(line, `"cell":"sfo"`) {
				return
			}
		}
	}
}
