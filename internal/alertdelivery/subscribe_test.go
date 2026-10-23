package alertdelivery

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

type subscriptionTerminal struct {
	bytes.Buffer
	input io.Reader
}

func (terminal *subscriptionTerminal) Read(p []byte) (int, error) { return terminal.input.Read(p) }

func TestPushTopicValidation(t *testing.T) {
	if !validPushTopic(fixtureTopic) || !validPushTopic(strings.Repeat("b", 43)) {
		t.Fatal("long URL-safe fixture topic refused")
	}
	for _, topic := range []string{"", "short", strings.Repeat("b", 42), strings.Repeat("b", 129), fixtureTopic + "\r\n", fixtureTopic + "/path", fixtureTopic + "?query", fixtureTopic + "%2f"} {
		if validPushTopic(topic) {
			t.Fatal("unsafe topic accepted")
		}
	}
}

func TestSubscribeRejectsNonTTYBeforeReadingSecrets(t *testing.T) {
	input, output := os.Stdin, os.Stdout
	defer func() { os.Stdin, os.Stdout = input, output }()
	file, err := os.CreateTemp(t.TempDir(), "non-tty")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	os.Stdin, os.Stdout = file, file
	r := relay{readTopic: func(context.Context) (string, error) {
		t.Fatal("non-TTY invocation read a secret")
		return "", nil
	}}
	if err := r.subscribe(t.Context()); err == nil || strings.Contains(err.Error(), fixtureTopic) {
		t.Fatal("non-TTY invocation was accepted or exposed a topic")
	}
	data, err := os.ReadFile(file.Name())
	if err != nil || len(data) != 0 {
		t.Fatal("non-TTY invocation wrote output")
	}
}

func TestSubscriptionWaitsForEnterAndPostsOnlyToLoopback(t *testing.T) {
	for _, confirm := range []bool{false, true} {
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
			if !strings.Contains(terminal.String(), "https://ntfy.sh/"+fixtureTopic) {
				t.Fatal("terminal did not receive subscription link")
			}
		})
	}
}

func TestSubscriptionFailuresAreSanitized(t *testing.T) {
	for _, transportFails := range []bool{false, true} {
		terminal := &subscriptionTerminal{input: strings.NewReader("\n")}
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			if transportFails {
				return nil, errors.New(fixtureTopic)
			}
			return &http.Response{StatusCode: 502, Body: io.NopCloser(strings.NewReader(fixtureTopic))}, nil
		})}
		err := confirmSubscription(t.Context(), terminal, fixtureTopic, client)
		if err == nil || strings.Contains(err.Error(), fixtureTopic) {
			t.Fatal("subscription failure accepted or leaked provider detail")
		}
	}
	terminal := &subscriptionTerminal{input: strings.NewReader("\n")}
	if err := confirmSubscription(t.Context(), terminal, "invalid", nil); err == nil || terminal.Len() != 0 {
		t.Fatal("invalid secret printed or accepted")
	}
}

func TestHelpUsageProbeDoesNotStartDaemon(t *testing.T) {
	if err := Run(t.Context(), []string{"--help"}); err == nil || err.Error() != "usage: ts-orch alert-delivery" {
		t.Fatalf("installer usage probe changed: %v", err)
	}
}
