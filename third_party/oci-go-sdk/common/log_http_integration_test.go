package common

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type debugHTTPFormatProbe struct {
	calls int
}

func (probe *debugHTTPFormatProbe) String() string {
	probe.calls++
	return "Authorization: fixture-secret"
}

type debugHTTPCustomLogger struct {
	DefaultSDKLogger
	output *bytes.Buffer
}

func (logger *debugHTTPCustomLogger) Log(_ int, format string, values ...any) error {
	_, err := fmt.Fprintf(logger.output, format, values...)
	return err
}

func TestDebugfDuringHTTPRequestMarshaling(t *testing.T) {
	originalLogger := defaultLogger
	t.Cleanup(func() { SetSDKLogger(originalLogger) })
	const expectedBody = `{"authorization":"fixture-secret","name":"retained"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if request.Method != http.MethodPost || request.URL.Path != "/requests" || string(body) != expectedBody {
			http.Error(w, fmt.Sprintf("unexpected SDK request: %s %s body %s", request.Method, request.URL.Path, body), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "accepted")
	}))
	defer server.Close()
	for _, tc := range []struct {
		name    string
		level   int
		pointer bool
		custom  bool
	}{
		{name: "default value no logging", level: noLogging},
		{name: "default pointer no logging", level: noLogging, pointer: true},
		{name: "default value info", level: infoLogging},
		{name: "default pointer info", level: infoLogging, pointer: true},
		{name: "default value debug", level: debugLogging},
		{name: "default pointer debug", level: debugLogging, pointer: true},
		{name: "default value verbose", level: verboseLogging},
		{name: "default pointer verbose", level: verboseLogging, pointer: true},
		{name: "custom below debug", level: noLogging, custom: true},
		{name: "custom verbose", level: verboseLogging, custom: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			capture := log.New(&output, "", 0)
			logger := DefaultSDKLogger{
				currentLoggingLevel: tc.level,
				verboseLogger:       capture,
				debugLogger:         capture,
				infoLogger:          capture,
				nullLogger:          log.New(io.Discard, "", 0),
			}
			var selected sdkLogger = logger
			if tc.pointer {
				selected = &logger
			}
			if tc.custom {
				selected = &debugHTTPCustomLogger{DefaultSDKLogger: logger, output: &output}
			}
			SetSDKLogger(selected)
			secret, name := "fixture-secret", "retained"
			request := struct {
				Body struct {
					Authorization *string `json:"authorization" mandatory:"false"`
					Name          *string `json:"name" mandatory:"false"`
					Optional      *string `json:"optional" mandatory:"false"`
				} `contributesTo:"body"`
			}{}
			request.Body.Authorization = &secret
			request.Body.Name = &name
			wire, err := MakeDefaultHTTPRequestWithTaggedStruct(http.MethodPost, "/requests", request)
			if err != nil {
				t.Fatal(err)
			}
			if wire.Body == nil {
				t.Fatal("SDK marshaler returned no body")
			}
			wire.URL.Scheme = "http"
			wire.URL.Host = server.Listener.Addr().String()
			response, err := server.Client().Do(&wire)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusCreated || string(body) != "accepted" {
				t.Fatalf("SDK HTTP response = %d %q, want 201 accepted", response.StatusCode, body)
			}
			// Marshaler debug arguments are strings; this probe checks formatting under the same logger.
			var probe debugHTTPFormatProbe
			Debugf("%s", &probe)
			wantCalls := 0
			if tc.custom || tc.level >= debugLogging {
				wantCalls = 1
			}
			if probe.calls != wantCalls {
				t.Fatalf("formatting calls = %d, want %d", probe.calls, wantCalls)
			}
			if strings.Contains(output.String(), secret) {
				t.Fatalf("log contains unredacted credential: %s", output.String())
			}
			if wantCalls == 0 && output.Len() != 0 {
				t.Fatalf("disabled logger emitted: %s", output.String())
			}
			if wantCalls == 1 && !strings.Contains(output.String(), "Authorization: REDACTED") {
				t.Fatalf("logger did not emit redacted probe: %s", output.String())
			}
			if wantCalls == 1 && !strings.Contains(output.String(), "Adjusting tag: mandatory is false and json tag is valid on field: Authorization") {
				t.Fatalf("logger did not emit SDK field traversal: %s", output.String())
			}
			if tc.level == verboseLogging && !strings.Contains(output.String(), `"authorization":"REDACTED"`) {
				t.Fatalf("logger did not emit redacted marshaled body: %s", output.String())
			}
		})
	}
}
