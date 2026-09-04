package cloudflare

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestSecretValueLifecycleNeverReturnsValue(t *testing.T) {
	const value = "hmac-material-that-must-not-leak"
	c, ft := testClient(func(call fakeCall) (int, string, http.Header) {
		switch {
		case call.Method == http.MethodPost && strings.HasSuffix(call.Path, "/secrets/CAPABILITY_CURRENT/versions"):
			var body map[string]string
			if err := json.Unmarshal([]byte(call.Body), &body); err != nil {
				t.Fatal(err)
			}
			if body["value_base64"] != base64.StdEncoding.EncodeToString([]byte(value)) || strings.Contains(call.Body, value) {
				t.Fatalf("secret value was not protected in request: %s", call.Body)
			}
			return okEnvelope(`{"name":"CAPABILITY_CURRENT","version":7}`)
		case call.Method == http.MethodPost && strings.HasSuffix(call.Path, "/versions/7/activate"):
			return okEnvelope("null")
		case call.Method == http.MethodDelete && strings.HasSuffix(call.Path, "/versions/7"):
			return okEnvelope("null")
		default:
			return failEnvelope(http.StatusNotFound, 10004, "not found")
		}
	})
	metadata, err := c.WriteSecretValue(context.Background(), "rotation", "CAPABILITY_CURRENT", []byte(value))
	if err != nil || metadata.Version != 7 {
		t.Fatalf("write metadata=%+v err=%v", metadata, err)
	}
	if err := c.ActivateSecretVersion(context.Background(), "rotation", "CAPABILITY_CURRENT", 7); err != nil {
		t.Fatal(err)
	}
	if err := c.RetireSecretVersion(context.Background(), "rotation", "CAPABILITY_CURRENT", 7); err != nil {
		t.Fatal(err)
	}
	for _, call := range ft.recorded() {
		if strings.Contains(call.String(), value) {
			t.Fatalf("secret leaked into call record: %s", call)
		}
	}
}
