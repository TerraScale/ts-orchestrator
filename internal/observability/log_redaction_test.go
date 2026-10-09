package observability

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

func redactionLogger(t *testing.T, format string, attrs ...slog.Attr) (*slog.Logger, *bytes.Buffer, *EventBus) {
	t.Helper()
	output := new(bytes.Buffer)
	bus := NewEventBus(256)
	logger, err := NewLogger(output, LogConfig{Format: format}, bus, attrs...)
	if err != nil {
		t.Fatal(err)
	}
	return logger, output, bus
}

func assertNoLogSecrets(t *testing.T, output *bytes.Buffer, bus *EventBus, secrets ...string) {
	t.Helper()
	events, err := json.Marshal(bus.Recent(0))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range secrets {
		if strings.Contains(output.String(), secret) || bytes.Contains(events, []byte(secret)) {
			t.Fatalf("credential %q escaped redaction: output=%s events=%s", secret, output.String(), events)
		}
	}
	if !utf8.Valid(output.Bytes()) || !utf8.Valid(events) {
		t.Fatal("invalid UTF8 in a sink")
	}
}

func TestLogRedactionCredentialsBothSinks(t *testing.T) {
	t.Parallel()
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJsb2dUZXN0In0.signatureSecret123"
	spacedJWT := base64.RawURLEncoding.EncodeToString([]byte("{\n \"alg\":\"HS256\"}")) + ".eyJzdWIiOiJsb2dUZXN0In0.spacedJWTSecret123"
	seed := "SU" + strings.Repeat("A", 56)
	pem := "-----BEGIN PRIVATE KEY-----\npemPayloadSecret123\n-----END PRIVATE KEY-----"
	freeText := "request Bearer bearerSecret123 jwt=" + jwt + " spaced=" + spacedJWT + " seed=" + seed + " key=" + pem +
		" url=https://urlUserSecret:urlPasswordSecret@example.test/path?access_token=querySecret123&mode=normal"
	for _, format := range []string{"json", "logfmt"} {
		t.Run(format, func(t *testing.T) {
			logger, output, bus := redactionLogger(t, format, slog.String("cell", "gru"), slog.String("AUTHORIZATION", "staticSecret123"))
			logger = logger.With("component", "placement", "Cookie", "scopedSecret123").WithGroup("request")
			logger.Warn(freeText,
				"error", errors.New(freeText),
				"details", freeText,
				"pAsS_wOrD", "passwordSecret123", "access-key", "accessKeySecret123",
				"client_credential", "credentialSecret123", "Session-ID", "sessionSecret123",
				"nested", slog.GroupValue(slog.String("private-key", "privateKeySecret123")),
			)
			logger.WithGroup("client-secrets").Warn("sensitive group", "innocent", "groupSecret123")
			logger.Warn("nested sensitive group", slog.Group("auth_token", "innocent", "nestedGroupSecret123"))
			assertNoLogSecrets(t, output, bus, "bearerSecret123", jwt, "signatureSecret123", spacedJWT, "spacedJWTSecret123", seed, "pemPayloadSecret123",
				"urlUserSecret", "urlPasswordSecret", "querySecret123", "staticSecret123", "scopedSecret123",
				"passwordSecret123", "accessKeySecret123", "credentialSecret123", "sessionSecret123",
				"privateKeySecret123", "groupSecret123", "nestedGroupSecret123")
			if len(bus.Recent(0)) != 3 || !strings.Contains(output.String(), "mode=normal") {
				t.Fatalf("normal URL data or events lost: %s %+v", output, bus.Recent(0))
			}
			if strings.Contains(output.String(), logTruncatedKey) {
				t.Fatalf("redaction alone should not claim truncation: %s", output)
			}
		})
	}
}

func TestLogRedactionNormalSemantics(t *testing.T) {
	t.Parallel()
	for _, format := range []string{"json", "logfmt"} {
		t.Run(format, func(t *testing.T) {
			logger, output, bus := redactionLogger(t, format, slog.String("cell", "gru"), slog.String("role", "controller"))
			logger.Info("routine tick", "count", 4, "ready", true, "elapsed", 2*time.Second, "version", "1.2.3", "host", "controller.example.test")
			logger.Info("member ready", EventKey, true)
			logger.With(ComponentKey, "placement").Warn("awaiting host", "reason", "not ready")
			logger.With(ComponentKey, "placement").Warn("awaiting host", "reason", "not ready")
			logger.WithGroup("lease").With("epoch", 7).WithGroup("").Warn("renewal", "valid", true)
			events := bus.Recent(0)
			if len(events) != 3 || events[0].Message != "member ready" || events[1].Component != "placement" || events[1].Attrs["reason"] != "not ready" || events[2].Attrs["lease.valid"] != "true" {
				t.Fatalf("event semantics changed: %+v", events)
			}
			if _, ok := events[1].Attrs["cell"]; ok {
				t.Fatal("static identity copied into event")
			}
			if _, ok := events[2].Attrs["lease.epoch"]; ok {
				t.Fatal("ordinary scoped attribute copied into event")
			}
			if strings.Count(output.String(), "\n") != 5 || strings.Contains(output.String(), logTruncatedKey) {
				t.Fatalf("normal lines changed: %s", output)
			}
			if format == "json" {
				var first map[string]any
				if err := json.Unmarshal(bytes.Split(output.Bytes(), []byte("\n"))[0], &first); err != nil {
					t.Fatal(err)
				}
				if first["count"] != float64(4) || first["ready"] != true || first["elapsed"] != float64(2*time.Second) {
					t.Fatalf("typed values changed: %+v", first)
				}
			} else if !strings.Contains(output.String(), "count=4 ready=true elapsed=2s") {
				t.Fatalf("typed values changed: %s", output)
			}
		})
	}
}

func TestLogRedactionScopeOrderAndNames(t *testing.T) {
	t.Parallel()
	for _, format := range []string{"json", "logfmt"} {
		t.Run(format, func(t *testing.T) {
			logger, output, bus := redactionLogger(t, format)
			logger.With("root", "a").WithGroup("outer").With("before", "b").WithGroup("inner").Warn("scopes", "after", "c")
			logger.WithGroup("Bearer nameSecret123").Warn("names", "Bearer keySecret123", "safe")
			logger.With(slog.Group("", slog.String(ComponentKey, "first")), ComponentKey, "last").Warn("inline component")
			logger.With(ComponentKey, "first", slog.Group("", slog.String(ComponentKey, "last"))).Warn("inline override")
			assertNoLogSecrets(t, output, bus, "nameSecret123", "keySecret123")
			if bus.Recent(0)[0].Attrs["outer.inner.after"] != "c" {
				t.Fatalf("record scope changed: %+v", bus.Recent(0))
			}
			if format == "json" {
				var line map[string]any
				if err := json.Unmarshal(bytes.Split(output.Bytes(), []byte("\n"))[0], &line); err != nil {
					t.Fatal(err)
				}
				outer := line["outer"].(map[string]any)
				if line["root"] != "a" || outer["before"] != "b" || outer["inner"].(map[string]any)["after"] != "c" {
					t.Fatalf("WithAttrs/WithGroup order changed: %+v", line)
				}
				for _, line := range bytes.Split(bytes.TrimSpace(output.Bytes()), []byte("\n"))[2:] {
					var decoded map[string]any
					if err := json.Unmarshal(line, &decoded); err != nil {
						t.Fatal(err)
					}
					if decoded[ComponentKey] != "last" {
						t.Fatalf("inline/scoped component order changed: %s", line)
					}
				}
			} else if !strings.Contains(output.String(), "root=a outer.before=b outer.inner.after=c") {
				t.Fatalf("WithAttrs/WithGroup order changed: %s", output)
			}
		})
	}
}

type mutableLogValue struct{ value map[string]any }

func (v *mutableLogValue) LogValue() slog.Value { return slog.AnyValue(v.value) }

type mutableLogError struct{ text string }

func (e *mutableLogError) Error() string { return e.text }

type mutableLogStringer struct{ text string }

func (v *mutableLogStringer) String() string { return v.text }

type cyclicLogValue struct{}

func (v cyclicLogValue) LogValue() slog.Value { return slog.AnyValue(v) }

type panicLogValue struct{}

func (panicLogValue) LogValue() slog.Value { panic("panicCredential123") }

func TestLogRedactionFrozenScopesAndConcurrency(t *testing.T) {
	t.Parallel()
	for _, format := range []string{"json", "logfmt"} {
		t.Run(format, func(t *testing.T) {
			logger, output, bus := redactionLogger(t, format)
			items := []string{"original", "Bearer scopedBearer123"}
			values := map[string]any{"items": items, "password": "mapSecret123", "count": 7}
			valuer := &mutableLogValue{value: values}
			errValue := &mutableLogError{text: "original error Bearer frozenErrorSecret123"}
			stringValue := &mutableLogStringer{text: "original string Bearer frozenStringSecret123"}
			groupAttrs := []slog.Attr{slog.String("value", "original group"), slog.String("token", "frozenGroupSecret123")}
			scoped := logger.With("frozen", valuer, "error", errValue, "stringer", stringValue,
				slog.Attr{Key: "group", Value: slog.GroupValue(groupAttrs...)})
			errValue.text = "mutatedErrorSecret123"
			stringValue.text = "mutatedStringSecret123"
			groupAttrs[0] = slog.String("value", "mutatedGroupSecret123")
			items[0] = "mutatedValue123"
			values["password"] = "mutatedPassword123"
			values["new"] = "mutatedMap123"
			valuer.value = map[string]any{"changed": "mutatedValuer123"}
			var wg sync.WaitGroup
			for worker := range 4 {
				wg.Go(func() {
					for index := range 20 {
						scoped.WithGroup("work").With("worker", worker).Warn(fmt.Sprintf("job %d/%d", worker, index), "index", index)
					}
				})
			}
			// Mutations after With must never race with the handler.
			wg.Go(func() {
				for index := range 100 {
					items[0] = fmt.Sprint(index)
					values["count"] = index
					valuer.value = map[string]any{"index": index}
				}
			})
			wg.Wait()
			assertNoLogSecrets(t, output, bus, "scopedBearer123", "mapSecret123", "mutatedValue123", "mutatedPassword123", "mutatedMap123", "mutatedValuer123",
				"frozenErrorSecret123", "frozenStringSecret123", "frozenGroupSecret123", "mutatedErrorSecret123", "mutatedStringSecret123", "mutatedGroupSecret123")
			if !strings.Contains(output.String(), "original") || strings.Count(output.String(), "\n") != 80 || len(bus.Recent(0)) != 80 {
				t.Fatalf("frozen value or concurrency lost: %s events=%d", output, len(bus.Recent(0)))
			}
		})
	}
}

func TestLogRedactionBoundsAndBoundaryCredentials(t *testing.T) {
	t.Parallel()
	for _, format := range []string{"json", "logfmt"} {
		t.Run(format, func(t *testing.T) {
			logger, output, bus := redactionLogger(t, format)
			jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJib3VuZCJ9.boundaryJWT123"
			seed := "SU" + strings.Repeat("B", 56)
			cases := []struct{ credential, secret string }{
				{"Bearer boundaryBearer123", "boundaryBearer123"},
				{jwt, "eyJhbGciOiJIUzI1NiJ9"},
				{seed, "SUBBBBBB"},
				{"-----BEGIN PRIVATE KEY-----\nboundaryPEM123\n-----END PRIVATE KEY-----", "boundaryPEM123"},
				{"https://boundaryUser123:boundaryPassword123@example.test/?secret=boundaryQuery123", "boundaryUser123"},
			}
			for i, tc := range cases {
				logger.Warn(fmt.Sprintf("%d ", i)+strings.Repeat("a", maxLogMessageBytes-16)+" "+tc.credential+strings.Repeat("z", 100),
					"value", strings.Repeat("a", maxLogValueBytes-8)+" "+tc.credential+strings.Repeat("z", 100))
				assertNoLogSecrets(t, output, bus, tc.secret)
			}
			logger.Warn(strings.Repeat("€", 2000)+"\xff", "bad\xffkey", "bad\xffvalue", "long", strings.Repeat("€", 1000),
				strings.Repeat("k", 100), "ok")
			logger.WithGroup(strings.Repeat("g", 100)).Warn("long group", "value", strings.Repeat("x", maxLogScanBytes)+"Bearer scanBoundary123")
			logger.Warn(strings.Repeat("x", maxLogScanBytes) + "Bearer messageScanBoundary123")
			logger.Warn("cycles", "valuer", cyclicLogValue{}, "panic", panicLogValue{})
			assertNoLogSecrets(t, output, bus, "boundaryBearer123", "boundaryJWT123", "boundaryPEM123", "boundaryUser123", "boundaryPassword123", "boundaryQuery123", "scanBoundary123", "messageScanBoundary123", "panicCredential123")
			for _, event := range bus.Recent(0) {
				if len(event.Message) > maxLogMessageBytes || !utf8.ValidString(event.Message) {
					t.Fatalf("unbounded message: %d", len(event.Message))
				}
				marked := false
				for key, value := range event.Attrs {
					if len(value) > maxLogValueBytes || !utf8.ValidString(value) {
						t.Fatalf("unbounded value %q: %d", key, len(value))
					}
					marked = marked || strings.HasSuffix(key, logTruncatedKey) && value == "true"
				}
				if !marked {
					t.Fatalf("truncation not visible: %+v", event)
				}
			}
			if !strings.Contains(output.String(), logTruncatedKey) {
				t.Fatal("formatted output missing truncation marker")
			}
			if format == "json" {
				for line := range bytes.SplitSeq(bytes.TrimSpace(output.Bytes()), []byte("\n")) {
					var decoded map[string]any
					if err := json.Unmarshal(line, &decoded); err != nil {
						t.Fatal(err)
					}
					checkLogBounds(t, decoded, 0)
				}
			} else {
				checkLogfmtBounds(t, output.String())
			}
		})
	}
}

func checkLogfmtBounds(t *testing.T, output string) {
	t.Helper()
	for line := range strings.SplitSeq(strings.TrimSpace(output), "\n") {
		count := 0
		for line != "" {
			key, rest, ok := strings.Cut(line, "=")
			if !ok {
				t.Fatalf("invalid logfmt: %q", line)
			}
			var value string
			if strings.HasPrefix(rest, `"`) {
				quoted, err := strconv.QuotedPrefix(rest)
				if err != nil {
					t.Fatal(err)
				}
				value, err = strconv.Unquote(quoted)
				if err != nil {
					t.Fatal(err)
				}
				line = strings.TrimPrefix(rest[len(quoted):], " ")
			} else {
				value, line, _ = strings.Cut(rest, " ")
			}
			if key == "time" || key == "level" || key == "msg" {
				continue
			}
			count++
			parts := strings.Split(key, ".")
			if len(parts)-1 > maxLogDepth {
				t.Fatalf("unbounded logfmt group depth: %q", key)
			}
			for _, name := range parts {
				if len(name) > maxLogNameBytes || !utf8.ValidString(name) {
					t.Fatalf("unbounded logfmt name: %q", name)
				}
			}
			if len(value) > maxLogValueBytes || !utf8.ValidString(value) {
				t.Fatalf("unbounded logfmt value: %d", len(value))
			}
		}
		if count > maxLogAttrs {
			t.Fatalf("unbounded logfmt attribute count: %d", count)
		}
	}
}

func checkLogBounds(t *testing.T, object map[string]any, depth int) int {
	t.Helper()
	count := 0
	for key, value := range object {
		if depth == 0 && (key == "time" || key == "level" || key == "msg") {
			continue
		}
		count++
		if len(key) > maxLogNameBytes || !utf8.ValidString(key) {
			t.Fatalf("unbounded key %q", key)
		}
		switch v := value.(type) {
		case map[string]any:
			if depth >= maxLogDepth {
				t.Fatalf("group depth exceeded at %q", key)
			}
			count += checkLogBounds(t, v, depth+1)
		case string:
			if len(v) > maxLogValueBytes || !utf8.ValidString(v) {
				t.Fatalf("unbounded string at %q: %d", key, len(v))
			}
		}
	}
	if count > maxLogAttrs {
		t.Fatalf("attribute budget exceeded: %d", count)
	}
	return count
}

func TestLogRedactionCountDepthAndMetadata(t *testing.T) {
	t.Parallel()
	for _, format := range []string{"json", "logfmt"} {
		t.Run(format, func(t *testing.T) {
			logger, output, bus := redactionLogger(t, format)
			args := make([]any, 0, 200)
			for i := range 100 {
				args = append(args, fmt.Sprintf("attr%d", i), i)
			}
			args = append(args, ComponentKey, "placement", EventKey, true)
			logger.Info("late metadata", args...)
			scoped := logger.With(args...)
			scoped.Info("full scope", EventKey, true, ComponentKey, "runtime")
			for range 100 {
				scoped = scoped.With(ComponentKey, "updated")
			}
			scoped.Warn("late scoped component")
			deep := logger
			for range 100 {
				deep = deep.WithGroup("group")
			}
			deep.With("hidden", "deepScopeSecret123").Warn("deep scopes", "hidden", "deepRecordSecret123")
			value := slog.StringValue("deepNestedSecret123")
			for range 100 {
				value = slog.GroupValue(slog.Attr{Key: "nested", Value: value})
			}
			logger.Warn("deep attr", slog.Attr{Key: "root", Value: value})
			assertNoLogSecrets(t, output, bus, "deepScopeSecret123", "deepRecordSecret123", "deepNestedSecret123")
			events := bus.Recent(0)
			if len(events) != 5 || events[0].Component != "placement" || events[1].Component != "runtime" || events[2].Component != "updated" {
				t.Fatalf("metadata lost under truncation: %+v", events)
			}
			for _, event := range events {
				marked := false
				for key, value := range event.Attrs {
					marked = marked || strings.HasSuffix(key, logTruncatedKey) && value == "true"
				}
				if !marked || len(event.Attrs) > maxLogAttrs {
					t.Fatalf("truncated scope not visible/bounded: %+v", event)
				}
			}
			if format == "json" {
				for line := range bytes.SplitSeq(bytes.TrimSpace(output.Bytes()), []byte("\n")) {
					var decoded map[string]any
					if err := json.Unmarshal(line, &decoded); err != nil {
						t.Fatal(err)
					}
					checkLogBounds(t, decoded, 0)
				}
			} else {
				checkLogfmtBounds(t, output.String())
			}
		})
	}
}

type recordCapture struct{ record slog.Record }

func (*recordCapture) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordCapture) Handle(_ context.Context, r slog.Record) error {
	h.record = r
	return nil
}
func (h *recordCapture) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordCapture) WithGroup(string) slog.Handler      { return h }

func TestLogRedactionRecordTimeLevelAndSource(t *testing.T) {
	t.Parallel()
	capture := new(recordCapture)
	h := &redactingHandler{next: capture}
	pcs := make([]uintptr, 1)
	runtime.Callers(1, pcs)
	at := time.Date(2026, 10, 9, 12, 0, 0, 123, time.FixedZone("test", 3600))
	r := slog.NewRecord(at, slog.LevelWarn, "Bearer sourceSecret123", pcs[0])
	r.AddAttrs(slog.Int("epoch", 7), slog.Bool(EventKey, true))
	if err := h.Handle(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	if capture.record.Time != at || capture.record.Level != slog.LevelWarn || capture.record.PC != pcs[0] || capture.record.Message != "Bearer "+redactedLogValue {
		t.Fatalf("record metadata changed: %+v", capture.record)
	}
	if r.Message != "Bearer sourceSecret123" || r.NumAttrs() != 2 {
		t.Fatal("caller record mutated")
	}
}
