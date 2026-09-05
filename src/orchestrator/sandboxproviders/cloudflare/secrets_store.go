package cloudflare

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"time"
)

func secretDecode(body []byte, out any) bool {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	return decoder.Decode(out) == nil && decoder.Decode(&struct{}{}) == io.EOF
}
func (s *Server) secretEndpoint(w http.ResponseWriter, r *http.Request, p []string, body []byte, fault FaultStep) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(p) == 1 && p[0] == "stores" {
		switch r.Method {
		case http.MethodGet:
			values := make([]secretStore, 0, len(s.secretStores))
			for _, v := range s.secretStores {
				values = append(values, v)
			}
			sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
			start, end, number, total := page(r, len(values))
			s.secretPage(w, values[start:end], number, total)
			return
		case http.MethodPost:
			var in struct {
				Name string `json:"name"`
			}
			if !secretDecode(body, &in) || in.Name == "" {
				s.writeError(w, 400, 1003, "invalid secret store")
				return
			}
			for _, v := range s.secretStores {
				if v.Name == in.Name {
					s.writeError(w, 409, 1006, "secret store exists")
					return
				}
			}
			now := time.Now().UTC()
			store := secretStore{ID: id("store", &s.nextID), Name: in.Name, Created: now, Modified: now}
			s.secretStores[store.ID] = store
			s.secrets[store.ID] = map[string]secret{}
			s.writeMutation(r, w, body, 200, store, nil, fault)
			return
		}
	}
	if len(p) < 2 || p[0] != "stores" {
		s.writeError(w, 404, 1000, "secret store not found")
		return
	}
	store, exists := s.secretStores[p[1]]
	if !exists {
		s.writeError(w, 404, 10004, "secret store not found")
		return
	}
	if len(p) == 2 {
		switch r.Method {
		case http.MethodGet:
			s.envelope(w, 200, store, nil)
			return
		case http.MethodDelete:
			if len(s.secrets[store.ID]) != 0 && r.URL.Query().Get("force") != "true" {
				s.writeError(w, 409, 1006, "secret store is not empty")
				return
			}
			delete(s.secretStores, store.ID)
			delete(s.secrets, store.ID)
			s.writeMutation(r, w, body, 200, nil, nil, fault)
			return
		}
	}
	if len(p) == 3 && p[2] == "secrets" {
		switch r.Method {
		case http.MethodGet:
			values := make([]secret, 0, len(s.secrets[store.ID]))
			for _, v := range s.secrets[store.ID] {
				values = append(values, v)
			}
			sort.Slice(values, func(i, j int) bool { return values[i].ID < values[j].ID })
			start, end, number, total := page(r, len(values))
			s.secretPage(w, values[start:end], number, total)
			return
		case http.MethodPost:
			var inputs []struct {
				Name    string   `json:"name"`
				Value   *string  `json:"value"`
				Scopes  []string `json:"scopes"`
				Comment string   `json:"comment"`
			}
			if !secretDecode(body, &inputs) || len(inputs) == 0 {
				s.writeError(w, 400, 1003, "expected secret array")
				return
			}
			names := map[string]bool{}
			for _, v := range s.secrets[store.ID] {
				names[v.Name] = true
			}
			for _, in := range inputs {
				if in.Name == "" || in.Value == nil || len(*in.Value) > 65536 || len(in.Scopes) == 0 {
					s.writeError(w, 400, 1003, "invalid secret input")
					return
				}
				if names[in.Name] {
					s.writeError(w, 409, 1006, "secret name exists")
					return
				}
				names[in.Name] = true
			}
			out := make([]secret, 0, len(inputs))
			for _, in := range inputs {
				now := time.Now().UTC()
				v := secret{ID: id("secret", &s.nextID), StoreID: store.ID, Name: in.Name, Value: []byte(*in.Value), Status: "active", Created: now, Modified: now, Scopes: in.Scopes, Comment: in.Comment}
				s.secrets[store.ID][v.ID] = v
				out = append(out, v)
			}
			s.writeMutation(r, w, body, 200, out, nil, fault)
			return
		}
	}
	if len(p) != 4 || p[2] != "secrets" {
		s.writeError(w, 404, 1000, "secret resource not found")
		return
	}
	v, exists := s.secrets[store.ID][p[3]]
	if !exists {
		s.writeError(w, 404, 10004, "secret not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.envelope(w, 200, v, nil)
	case http.MethodPatch:
		var in struct {
			Value   *string  `json:"value"`
			Scopes  []string `json:"scopes"`
			Comment *string  `json:"comment"`
		}
		if !secretDecode(body, &in) || in.Value == nil && in.Scopes == nil && in.Comment == nil || in.Value != nil && len(*in.Value) > 65536 || in.Scopes != nil && len(in.Scopes) == 0 {
			s.writeError(w, 400, 1003, "invalid secret update")
			return
		}
		if in.Value != nil {
			clear(v.Value)
			v.Value = []byte(*in.Value)
		}
		if in.Scopes != nil {
			v.Scopes = in.Scopes
		}
		if in.Comment != nil {
			v.Comment = *in.Comment
		}
		v.Modified = time.Now().UTC()
		s.secrets[store.ID][v.ID] = v
		s.writeMutation(r, w, body, 200, v, nil, fault)
	case http.MethodDelete:
		clear(v.Value)
		delete(s.secrets[store.ID], v.ID)
		s.writeMutation(r, w, body, 200, nil, nil, fault)
	default:
		s.writeError(w, 405, 1005, "method not allowed")
	}
}
func (s *Server) secretPage(w http.ResponseWriter, result any, number, total int) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": result, "result_info": map[string]int{"page": number, "total_pages": total}})
}
