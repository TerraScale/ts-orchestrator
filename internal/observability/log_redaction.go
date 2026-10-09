package observability

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	maxLogMessageBytes = 4096
	maxLogAttrs        = 32
	maxLogNameBytes    = 64
	maxLogValueBytes   = 512
	maxLogDepth        = 8
	maxLogScanBytes    = 64 * 1024
	logTruncatedKey    = "log_truncated"
	redactedLogValue   = "[REDACTED]"
	omittedLogValue    = "[truncated]"
)

// Scoped values are prepared immediately, so downstream handlers never retain
// application objects. Two slots remain for record event/component metadata,
// one for a scoped component, and one for the truncation marker.
type redactingHandler struct {
	next      slog.Handler
	base      slog.Handler
	scopes    []logScope
	component slog.Attr
	used      int
	depth     int
	sensitive bool
	blocked   bool
	truncated bool
}

type logScope struct {
	attrs     []slog.Attr
	group     string
	component bool
}

func (h *redactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *redactingHandler) Handle(ctx context.Context, record slog.Record) error {
	s := logSanitizer{remaining: maxLogAttrs - 1 - h.used, truncated: h.truncated}
	if h.component.Key != "" {
		s.remaining--
	}
	clean := slog.NewRecord(record.Time, record.Level, s.text(record.Message, maxLogMessageBytes), record.PC)
	// Preserve selection and component even when ordinary attributes exhaust
	// the budget. This scan does not resolve or format application values.
	var event, component slog.Attr
	eventIndex, componentIndex := -1, -1
	index := 0
	record.Attrs(func(a slog.Attr) bool {
		if a.Key == EventKey && a.Value.Kind() == slog.KindBool {
			if event.Key == "" || !event.Value.Bool() {
				event = a
				eventIndex = index
			}
		}
		if a.Key == ComponentKey {
			component = a
			componentIndex = index
		}
		index++
		return true
	})
	// Reserve metadata capacity, but emit it in its original position so an
	// inline group and a root component keep their last-value-wins ordering.
	for _, a := range []*slog.Attr{&event, &component} {
		if a.Key != "" {
			*a, _ = s.attr(*a, h.depth, h.sensitive)
		}
	}
	index = -1
	record.Attrs(func(a slog.Attr) bool {
		index++
		if index == eventIndex {
			if event.Key != "" {
				clean.AddAttrs(event)
			}
			return true
		}
		if index == componentIndex {
			if component.Key != "" {
				clean.AddAttrs(component)
			}
			return true
		}
		if a.Key == ComponentKey || (a.Key == EventKey && eventIndex >= 0) {
			return true
		}
		if h.blocked || s.remaining <= 0 {
			s.truncated = true
			return true
		}
		if prepared, ok := s.attr(a, h.depth, h.sensitive); ok {
			clean.AddAttrs(prepared)
		}
		return true
	})
	if s.truncated {
		clean.AddAttrs(slog.Bool(logTruncatedKey, true))
	}
	return h.next.Handle(ctx, clean)
}

func (h *redactingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := *h
	s := logSanitizer{remaining: maxLogAttrs - 4 - h.used, truncated: h.truncated}
	componentIndex := -1
	// A root scoped component has its own slot, so adding it to an already
	// full scope still preserves component attribution without growing scope.
	if h.depth == 0 && !h.blocked {
		var component slog.Attr
		for i, a := range attrs {
			if a.Key == ComponentKey {
				component = a
				componentIndex = i
			}
		}
		if component.Key != "" {
			metadata := logSanitizer{remaining: 1}
			clone.component, _ = metadata.attr(component, maxLogDepth, false)
			s.truncated = s.truncated || metadata.truncated
		}
	}
	var clean []slog.Attr
	componentPosition := -1
	for i, a := range attrs {
		if h.depth == 0 && !h.blocked && a.Key == ComponentKey {
			if i == componentIndex {
				componentPosition = len(clean)
			}
			continue
		}
		if h.blocked || s.remaining <= 0 {
			s.truncated = true
			break
		}
		if prepared, ok := s.attr(a, h.depth, h.sensitive); ok {
			clean = append(clean, prepared)
		}
	}
	clone.used += maxLogAttrs - 4 - h.used - s.remaining
	clone.truncated = s.truncated
	if componentIndex >= 0 {
		clone.scopes = nil
		for _, scope := range h.scopes {
			if !scope.component {
				clone.scopes = append(clone.scopes, scope)
			}
		}
		if componentPosition < 0 {
			componentPosition = len(clean)
		}
		if componentPosition > 0 {
			clone.scopes = append(clone.scopes, logScope{attrs: clean[:componentPosition]})
		}
		clone.scopes = append(clone.scopes, logScope{component: true})
		if componentPosition < len(clean) {
			clone.scopes = append(clone.scopes, logScope{attrs: clean[componentPosition:]})
		}
	} else if len(clean) > 0 {
		clone.scopes = appendScope(h.scopes, logScope{attrs: clean})
	}
	clone.rebuild()
	return &clone
}

func (h *redactingHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	clone := *h
	clone.sensitive = h.sensitive || sensitiveLogKey(name)
	if h.blocked || h.depth >= maxLogDepth || h.used >= maxLogAttrs-4 {
		clone.blocked, clone.truncated = true, true
		return &clone
	}
	s := logSanitizer{}
	clone.scopes = appendScope(h.scopes, logScope{group: s.text(name, maxLogNameBytes)})
	clone.depth++
	clone.used++
	clone.truncated = h.truncated || s.truncated
	clone.rebuild()
	return &clone
}

func appendScope(scopes []logScope, scope logScope) []logScope {
	return append(append([]logScope(nil), scopes...), scope)
}

// Rebuild only on With operations. Keeping bounded prepared scope lets a
// replacement component discard the old value instead of accumulating attrs.
func (h *redactingHandler) rebuild() {
	if h.base == nil {
		h.base = h.next
	}
	h.next = h.base
	for _, scope := range h.scopes {
		if scope.component {
			h.next = h.next.WithAttrs([]slog.Attr{h.component})
		} else if scope.group != "" {
			h.next = h.next.WithGroup(scope.group)
		} else {
			h.next = h.next.WithAttrs(scope.attrs)
		}
	}
}

type logSanitizer struct {
	remaining int
	truncated bool
}

func (s *logSanitizer) attr(a slog.Attr, depth int, sensitive bool) (slog.Attr, bool) {
	if s.remaining <= 0 {
		s.truncated = true
		return slog.Attr{}, false
	}
	s.remaining--
	if a.Key == "" && a.Value.Kind() == slog.KindAny && a.Value.Any() == nil {
		return slog.Attr{}, false
	}
	key := s.text(a.Key, maxLogNameBytes)
	// Never invoke a valuer/error/stringer for a known sensitive field.
	if (sensitive || sensitiveLogKey(a.Key)) && !(a.Key == EventKey && a.Value.Kind() == slog.KindBool) {
		return slog.String(key, redactedLogValue), true
	}
	value := s.resolve(a.Value)
	if value.Kind() == slog.KindGroup {
		if depth >= maxLogDepth {
			s.truncated = true
			return slog.String(key, omittedLogValue), true
		}
		var children []slog.Attr
		for _, child := range value.Group() {
			if s.remaining <= 0 {
				s.truncated = true
				break
			}
			if prepared, ok := s.attr(child, depth+1, sensitive); ok {
				children = append(children, prepared)
			}
		}
		return slog.Attr{Key: key, Value: slog.GroupValue(children...)}, true
	}
	if value.Kind() == slog.KindString {
		value = slog.StringValue(s.text(value.String(), maxLogValueBytes))
	} else if value.Kind() == slog.KindAny {
		value = s.anyValue(value.Any(), depth)
	}
	return slog.Attr{Key: key, Value: value}, true
}

// Resolve one step at a time: slog.Value.Resolve can repeatedly invoke a
// valuer, and a valuer may return a group containing itself.
func (s *logSanitizer) resolve(value slog.Value) (resolved slog.Value) {
	defer func() {
		if recover() != nil {
			s.truncated = true
			resolved = slog.StringValue(omittedLogValue)
		}
	}()
	for range maxLogDepth {
		if value.Kind() != slog.KindLogValuer {
			return value
		}
		value = value.LogValuer().LogValue()
	}
	if value.Kind() == slog.KindLogValuer {
		s.truncated = true
		return slog.StringValue(omittedLogValue)
	}
	return value
}

func (s *logSanitizer) anyValue(value any, depth int) (result slog.Value) {
	defer func() {
		if recover() != nil {
			s.truncated = true
			result = slog.StringValue(omittedLogValue)
		}
	}()
	switch v := value.(type) {
	case nil:
		return slog.AnyValue(nil)
	case error:
		return slog.StringValue(s.text(v.Error(), maxLogValueBytes))
	case fmt.Stringer:
		return slog.StringValue(s.text(v.String(), maxLogValueBytes))
	}
	// Snapshot containers with a shared node/depth budget, never fmt or JSON
	// marshal the application's object (which could recurse or run custom code).
	frozen := s.snapshot(reflect.ValueOf(value), depth)
	encoded, err := json.Marshal(frozen)
	if err != nil {
		s.truncated = true
		return slog.StringValue(omittedLogValue)
	}
	return slog.StringValue(s.text(string(encoded), maxLogValueBytes))
}

func (s *logSanitizer) snapshot(value reflect.Value, depth int) any {
	if !value.IsValid() {
		return nil
	}
	if s.remaining <= 0 {
		s.truncated = true
		return omittedLogValue
	}
	s.remaining--
	if depth >= maxLogDepth {
		s.truncated = true
		return omittedLogValue
	}
	switch value.Kind() {
	case reflect.Interface, reflect.Pointer:
		if value.IsNil() {
			return nil
		}
		return s.snapshot(value.Elem(), depth+1)
	case reflect.String:
		return s.text(value.String(), maxLogValueBytes)
	case reflect.Bool:
		return value.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return value.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return value.Uint()
	case reflect.Float32, reflect.Float64:
		return value.Float()
	case reflect.Map:
		if value.Type().Key().Kind() != reflect.String {
			break
		}
		if value.Len() > s.remaining {
			s.truncated = true
			return omittedLogValue
		}
		// Collect only bounded maps; sorted traversal makes nested clipping stable.
		keys := value.MapKeys()
		slices.SortFunc(keys, func(a, b reflect.Value) int {
			return strings.Compare(a.String(), b.String())
		})
		frozen := map[string]any{}
		for _, mapKey := range keys {
			if s.remaining <= 0 {
				s.truncated = true
				break
			}
			key := mapKey.String()
			if sensitiveLogKey(key) {
				s.remaining--
				frozen[s.text(key, maxLogNameBytes)] = redactedLogValue
			} else {
				frozen[s.text(key, maxLogNameBytes)] = s.snapshot(value.MapIndex(mapKey), depth+1)
			}
		}
		return frozen
	case reflect.Slice, reflect.Array:
		if value.Kind() == reflect.Slice && value.Type().Elem().Kind() == reflect.Uint8 {
			if value.Len() > maxLogScanBytes {
				s.truncated = true
				return omittedLogValue
			}
			return s.text(string(value.Bytes()), maxLogValueBytes)
		}
		frozen := []any{}
		for i := 0; i < value.Len(); i++ {
			if s.remaining <= 0 {
				s.truncated = true
				break
			}
			frozen = append(frozen, s.snapshot(value.Index(i), depth+1))
		}
		return frozen
	}
	s.truncated = true
	return omittedLogValue
}

func sensitiveLogKey(key string) bool {
	if len(key) > maxLogScanBytes {
		return true
	}
	var normalized strings.Builder
	for _, r := range key {
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			normalized.WriteRune(r)
		}
	}
	name := normalized.String()
	for _, sensitive := range []string{"authorization", "cookie", "session", "password", "passwd", "token", "secret", "seed", "privatekey", "credential", "accesskey", "apikey"} {
		if strings.Contains(name, sensitive) {
			return true
		}
	}
	return false
}

var (
	logPEM    = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]+-----.*?(?:-----END [A-Z0-9 ]+-----|$)`)
	logBearer = regexp.MustCompile(`(?i)\bbearer\s+[^\s"'<>;,]+`)
	logJWT    = regexp.MustCompile(`\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)
	logSeed   = regexp.MustCompile(`\bS[A-Z2-7]{57,}`)
	logURL    = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>]+`)
	logQuery  = regexp.MustCompile(`[?&#][^&\s#"'<>]+=[^&\s#"'<>]*`)
)

func (s *logSanitizer) text(value string, limit int) string {
	// Fail closed rather than cutting an unfinished credential at the scan
	// boundary. All regex work is RE2 and limited to this input size.
	if len(value) > maxLogScanBytes {
		s.truncated = true
		return omittedLogValue
	}
	if !utf8.ValidString(value) {
		s.truncated = true
		value = strings.ToValidUTF8(value, "�")
	}
	value = logPEM.ReplaceAllString(value, redactedLogValue)
	value = logURL.ReplaceAllStringFunc(value, func(raw string) string {
		parsed, err := url.Parse(raw)
		if err != nil {
			return redactedLogValue
		}
		if parsed.User != nil {
			parsed.User = url.User(redactedLogValue)
		}
		return parsed.String()
	})
	value = logQuery.ReplaceAllStringFunc(value, func(raw string) string {
		key, _, _ := strings.Cut(raw[1:], "=")
		decoded, err := url.QueryUnescape(key)
		if err != nil || sensitiveLogKey(decoded) {
			return raw[:1] + key + "=" + redactedLogValue
		}
		return raw
	})
	value = logBearer.ReplaceAllString(value, "Bearer "+redactedLogValue)
	value = logJWT.ReplaceAllStringFunc(value, func(raw string) string {
		header, _, _ := strings.Cut(raw, ".")
		decoded, err := base64.RawURLEncoding.DecodeString(header)
		if err == nil && strings.HasPrefix(strings.TrimSpace(string(decoded)), "{") && json.Valid(decoded) {
			return redactedLogValue
		}
		return raw
	})
	value = logSeed.ReplaceAllString(value, redactedLogValue)
	if len(value) > limit {
		s.truncated = true
		cut := limit - len("...")
		for cut > 0 && !utf8.RuneStart(value[cut]) {
			cut--
		}
		value = value[:cut] + "..."
	}
	// Clone even short substrings: scoped strings must not pin large input buffers.
	return strings.Clone(value)
}
