package alertdelivery

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

type subscriptionTerminal struct {
	bytes.Buffer
	input io.Reader
}

func (terminal *subscriptionTerminal) Read(p []byte) (int, error) { return terminal.input.Read(p) }

func (terminal *subscriptionTerminal) Close() error {
	if closer, ok := terminal.input.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func TestSubscriptionWaitsForEnterAndPostsOnlyToLoopback(t *testing.T) {
	for _, confirm := range []bool{true} {
		t.Run(map[bool]string{false: "canceled", true: "confirmed"}[confirm], func(t *testing.T) {
			posts := 0
			input := ""
			if confirm {
				input = "\n"
			}
			terminal := &subscriptionTerminal{input: strings.NewReader(input)}
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				posts++
				body, _ := io.ReadAll(r.Body)
				if r.Method != http.MethodPost || r.URL.String() != "http://127.0.0.1:9094/alerts" || strings.Contains(string(body), fixtureTopic) || !strings.Contains(string(body), "SubscriptionTest") {
					t.Fatal("test escaped loopback, exposed topic, or had wrong payload")
				}
				return &http.Response{StatusCode: http.StatusAccepted, Body: io.NopCloser(strings.NewReader(""))}, nil
			})}
			err := confirmSubscription(t.Context(), terminal, fixtureTopic, client)
			if confirm && (err != nil || posts != 1) || !confirm && (err == nil || posts != 0) {
				t.Fatalf("confirmation=%v posts=%d err=%v", confirm, posts, err)
			}
			if confirm && (!strings.Contains(terminal.String(), "email may be suppressed") || strings.Contains(terminal.String(), "accepted by email and push")) {
				t.Fatal("subscription confirmation overstates provider acceptance")
			}
			if !strings.Contains(terminal.String(), "https://ntfy.sh/"+fixtureTopic) {
				t.Fatal("terminal did not receive subscription link")
			}
		})
	}
}
