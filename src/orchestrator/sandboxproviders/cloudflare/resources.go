package cloudflare

import (
	"encoding/json"
	"net/http"
	"sort"
)

type dnsRecord struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}
type wireRule struct {
	ID               string          `json:"id,omitempty"`
	Description      string          `json:"description,omitempty"`
	Expression       string          `json:"expression"`
	Action           string          `json:"action"`
	ActionParameters json.RawMessage `json:"action_parameters,omitempty"`
	Enabled          *bool           `json:"enabled,omitempty"`
}
type snippet struct {
	Name   string `json:"snippet_name"`
	source []byte
}
type snippetRule struct {
	SnippetName string `json:"snippet_name"`
	Expression  string `json:"expression"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}
type workerRoute struct {
	ID      string `json:"id,omitempty"`
	Pattern string `json:"pattern"`
	Script  string `json:"script,omitempty"`
}

func (s *Server) dnsEndpoint(w http.ResponseWriter, r *http.Request, p []string, body []byte, fault FaultStep) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(p) == 0 && r.Method == http.MethodGet {
		items := append([]dnsRecord(nil), s.dns...)
		sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
		start, end, num, total := page(r, len(items))
		per := end - start
		if per == 0 {
			per = 20
		}
		s.listEnvelope(w, http.StatusOK, items[start:end], resultInfo(num, per, total))
		return
	}
	if len(p) == 0 && r.Method == http.MethodPost {
		var v dnsRecord
		if json.Unmarshal(body, &v) != nil || v.Name == "" || v.Type == "" {
			s.writeError(w, 400, 1003, "invalid DNS record")
			return
		}
		v.ID = id("dns", &s.nextID)
		s.dns = append(s.dns, v)
		s.writeMutation(r, w, body, http.StatusOK, v, nil, fault)
		return
	}
	if len(p) != 1 {
		s.writeError(w, 404, 1000, "DNS record not found")
		return
	}
	target := pathUnescape(p[0])
	idx := -1
	for i := range s.dns {
		if s.dns[i].ID == target {
			idx = i
			break
		}
	}
	if idx < 0 {
		s.writeError(w, 404, 10004, "DNS record not found")
		return
	}
	current := etag(s.dns[idx])
	w.Header().Set("ETag", current)
	if !checkMatch(r, current) {
		s.writeError(w, 412, 1004, "etag does not match")
		return
	}
	switch r.Method {
	case http.MethodPatch, http.MethodPut:
		var v dnsRecord
		if json.Unmarshal(body, &v) != nil {
			s.writeError(w, 400, 1003, "invalid DNS record")
			return
		}
		v.ID = target
		if v.Name == "" {
			v.Name = s.dns[idx].Name
		}
		if v.Type == "" {
			v.Type = s.dns[idx].Type
		}
		if v.Content == "" {
			v.Content = s.dns[idx].Content
		}
		s.dns[idx] = v
		s.writeMutation(r, w, body, 200, v, nil, fault)
	case http.MethodDelete:
		s.dns = append(s.dns[:idx], s.dns[idx+1:]...)
		s.writeMutation(r, w, body, 200, nil, nil, fault)
	default:
		s.writeError(w, 405, 1005, "method not allowed")
	}
}

func (s *Server) rulesetEndpoint(w http.ResponseWriter, r *http.Request, p []string, body []byte, fault FaultStep) {
	if len(p) < 3 || p[0] != "phases" || p[2] != "entrypoint" {
		s.writeError(w, 404, 1000, "ruleset not found")
		return
	}
	phase := pathUnescape(p[1])
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Method == http.MethodGet {
		rules, ok := s.rules[phase]
		if !ok {
			s.writeError(w, 404, 10004, "phase not configured")
			return
		}
		s.envelope(w, 200, map[string]any{"rules": rules}, nil)
		return
	}
	if r.Method != http.MethodPut {
		s.writeError(w, 405, 1005, "method not allowed")
		return
	}
	var in struct {
		Rules []wireRule `json:"rules"`
	}
	if json.Unmarshal(body, &in) != nil {
		s.writeError(w, 400, 1003, "invalid ruleset")
		return
	}
	for i := range in.Rules {
		if in.Rules[i].ID == "" {
			in.Rules[i].ID = id("rule", &s.nextID)
		}
	}
	s.rules[phase] = in.Rules
	s.writeMutation(r, w, body, 200, nil, nil, fault)
}

func (s *Server) snippetEndpoint(w http.ResponseWriter, r *http.Request, p []string, body []byte, fault FaultStep) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(p) == 1 && p[0] == "snippet_rules" {
		current := map[string]any{"rules": s.snippetRules}
		switch r.Method {
		case http.MethodGet:
			s.envelope(w, 200, current, nil)
		case http.MethodPut:
			if !checkMatch(r, etag(current)) {
				s.writeError(w, http.StatusPreconditionFailed, 1008, "snippet rules changed")
				return
			}
			var in struct {
				Rules []snippetRule `json:"rules"`
			}
			if json.Unmarshal(body, &in) != nil || in.Rules == nil {
				s.writeError(w, 400, 1003, "invalid snippet rules")
				return
			}
			for _, rule := range in.Rules {
				if _, exists := s.snippets[rule.SnippetName]; !exists {
					s.writeError(w, 404, 10004, "Snippet code not found")
					return
				}
				if rule.Expression == "" {
					s.writeError(w, 400, 1003, "snippet expression required")
					return
				}
			}
			s.snippetRules = in.Rules
			s.writeMutation(r, w, body, 200, map[string]any{"rules": s.snippetRules}, nil, fault)
		default:
			s.writeError(w, 405, 1005, "method not allowed")
		}
		return
	}
	if len(p) == 0 && r.Method == http.MethodGet {
		names := make([]string, 0, len(s.snippets))
		for n := range s.snippets {
			names = append(names, n)
		}
		sort.Strings(names)
		out := make([]snippet, 0, len(names))
		for _, n := range names {
			out = append(out, s.snippets[n])
		}
		s.envelope(w, 200, out, nil)
		return
	}
	if len(p) == 2 && p[1] == "content" && r.Method == http.MethodGet {
		snippet, ok := s.snippets[pathUnescape(p[0])]
		if !ok || len(snippet.source) == 0 {
			s.writeError(w, 404, 10004, "Snippet code not found")
			return
		}
		writeCodeContent(w, "snippet.js", snippet.source)
		return
	}
	if len(p) == 1 {
		name := pathUnescape(p[0])
		snippet, present := s.snippets[name]
		switch r.Method {
		case http.MethodGet:
			if !present || len(snippet.source) == 0 {
				s.writeError(w, 404, 10004, "Snippet code not found")
				return
			}
			s.envelope(w, 200, snippet, nil)
			return
		case http.MethodPut:
			_, source, err := parseCodeUpload(r, body, "files", "snippet.js")
			if err != nil {
				s.writeError(w, 400, 1003, "invalid Snippet multipart upload")
				return
			}
			snippet.Name = name
			snippet.source = append([]byte(nil), source...)
			s.snippets[name] = snippet
			s.writeMutation(r, w, body, 200, snippet, nil, fault)
			return
		default:
			s.writeError(w, 405, 1005, "method not allowed")
			return
		}
	}
	s.writeError(w, 404, 1000, "snippet resource not found")
}

func (s *Server) routesEndpoint(w http.ResponseWriter, r *http.Request, p []string, body []byte, fault FaultStep) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(p) == 0 && r.Method == http.MethodGet {
		out := append([]workerRoute(nil), s.routes...)
		sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
		s.envelope(w, 200, out, nil)
		return
	}
	if len(p) == 0 && r.Method == http.MethodPost {
		var v workerRoute
		if json.Unmarshal(body, &v) != nil || v.Pattern == "" {
			s.writeError(w, 400, 1003, "invalid Worker route")
			return
		}
		v.ID = id("route", &s.nextID)
		s.routes = append(s.routes, v)
		s.writeMutation(r, w, body, 200, v, nil, fault)
		return
	}
	if len(p) != 1 {
		s.writeError(w, 404, 1000, "Worker route not found")
		return
	}
	target := pathUnescape(p[0])
	idx := -1
	for i := range s.routes {
		if s.routes[i].ID == target {
			idx = i
			break
		}
	}
	if idx < 0 {
		s.writeError(w, 404, 10004, "Worker route not found")
		return
	}
	switch r.Method {
	case http.MethodPut, http.MethodPatch:
		var v workerRoute
		if json.Unmarshal(body, &v) != nil {
			s.writeError(w, 400, 1003, "invalid Worker route")
			return
		}
		v.ID = target
		s.routes[idx] = v
		s.writeMutation(r, w, body, 200, v, nil, fault)
	case http.MethodDelete:
		s.routes = append(s.routes[:idx], s.routes[idx+1:]...)
		s.writeMutation(r, w, body, 200, nil, nil, fault)
	default:
		s.writeError(w, 405, 1005, "method not allowed")
	}
}

func (s *Server) cacheEndpoint(w http.ResponseWriter, r *http.Request, p []string, body []byte, fault FaultStep) {
	if len(p) != 1 || p[0] != "tiered_cache_smart_topology_enable" {
		s.writeError(w, 404, 1000, "cache setting not found")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Method == http.MethodGet {
		v := "off"
		if s.tiered {
			v = "on"
		}
		s.envelope(w, 200, map[string]string{"value": v}, nil)
		return
	}
	if r.Method != http.MethodPut {
		s.writeError(w, 405, 1005, "method not allowed")
		return
	}
	var in struct {
		Value string `json:"value"`
	}
	if json.Unmarshal(body, &in) != nil || (in.Value != "on" && in.Value != "off") {
		s.writeError(w, 400, 1003, "invalid cache setting")
		return
	}
	s.tiered = in.Value == "on"
	s.writeMutation(r, w, body, 200, nil, nil, fault)
}

func (s *Server) purgeEndpoint(w http.ResponseWriter, r *http.Request, body []byte, fault FaultStep) {
	if r.Method != http.MethodPost {
		s.writeError(w, 405, 1005, "method not allowed")
		return
	}
	var in struct {
		Tags []string `json:"tags"`
	}
	if json.Unmarshal(body, &in) != nil {
		s.writeError(w, 400, 1003, "invalid purge request")
		return
	}
	if len(in.Tags) > 100 {
		s.writeError(w, http.StatusBadRequest, 1009, "at most 100 cache tags per purge")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purges = append(s.purges, append([]string(nil), in.Tags...))
	s.writeMutation(r, w, body, 200, nil, nil, fault)
}

func (s *Server) settingsEndpoint(w http.ResponseWriter, r *http.Request, body []byte, fault FaultStep) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Method == http.MethodGet {
		out := make([]map[string]any, 0, len(s.settings))
		for k, v := range s.settings {
			out = append(out, map[string]any{"id": k, "value": v})
		}
		sort.Slice(out, func(i, j int) bool { return out[i]["id"].(string) < out[j]["id"].(string) })
		s.envelope(w, 200, out, nil)
		return
	}
	if r.Method != http.MethodPatch {
		s.writeError(w, 405, 1005, "method not allowed")
		return
	}
	var in struct {
		Items []struct {
			ID    string `json:"id"`
			Value string `json:"value"`
		} `json:"items"`
	}
	if json.Unmarshal(body, &in) != nil {
		s.writeError(w, 400, 1003, "invalid settings")
		return
	}
	for _, v := range in.Items {
		s.settings[v.ID] = v.Value
	}
	s.writeMutation(r, w, body, 200, nil, nil, fault)
}

func (s *Server) tlsEndpoint(w http.ResponseWriter, r *http.Request, p []string, body []byte, fault FaultStep) {
	if len(p) != 1 || p[0] != "total_tls" {
		s.writeError(w, 404, 1000, "TLS setting not found")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Method == http.MethodGet {
		s.envelope(w, 200, map[string]any{"enabled": s.totalTLS, "certificate_authority": "lets_encrypt"}, nil)
		return
	}
	if r.Method != http.MethodPost {
		s.writeError(w, 405, 1005, "method not allowed")
		return
	}
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if json.Unmarshal(body, &in) != nil {
		s.writeError(w, 400, 1003, "invalid TLS setting")
		return
	}
	s.totalTLS = in.Enabled
	s.writeMutation(r, w, body, 200, nil, nil, fault)
}

func (s *Server) listEnvelope(w http.ResponseWriter, status int, result any, info map[string]int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": status >= 200 && status < 300, "errors": []any{}, "messages": []any{}, "result": result, "result_info": info})
}
