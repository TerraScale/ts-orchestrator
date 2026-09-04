package cloudflare

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"time"
)

type namespace struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}
type secret struct {
	Name      string
	Value     []byte
	Version   int
	UpdatedAt time.Time
}
type workerVersion struct {
	ID        string          `json:"id"`
	Digest    string          `json:"digest"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}
type workerDeployment struct {
	ID       string              `json:"id"`
	Versions []deploymentVersion `json:"versions"`
	Status   string              `json:"status"`
}
type deploymentVersion struct {
	VersionID  string `json:"version_id"`
	Percentage int    `json:"percentage"`
}
type workerScript struct {
	Versions    map[string]workerVersion
	Deployments map[string]workerDeployment
	Active      string
}
type operation struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Polls  int
	Result any `json:"result,omitempty"`
	Err    string
}

func (s *Server) kvEndpoint(w http.ResponseWriter, r *http.Request, p []string, body []byte, fault FaultStep) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(p) == 0 {
		if r.Method == http.MethodGet {
			items := append([]namespace(nil), s.namespaces...)
			sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
			start, end, num, total := page(r, len(items))
			per := end - start
			if per == 0 {
				per = 20
			}
			s.listEnvelope(w, 200, items[start:end], resultInfo(num, per, total))
			return
		}
		if r.Method == http.MethodPost {
			var in struct {
				Title string `json:"title"`
			}
			if json.Unmarshal(body, &in) != nil || in.Title == "" {
				s.writeError(w, 400, 1003, "invalid KV namespace")
				return
			}
			for _, n := range s.namespaces {
				if n.Title == in.Title {
					s.writeError(w, 409, 1006, "namespace already exists")
					return
				}
			}
			n := namespace{ID: id("kv", &s.nextID), Title: in.Title}
			s.namespaces = append(s.namespaces, n)
			s.kv[n.ID] = map[string][]byte{}
			s.writeMutation(r, w, body, 200, n, nil, fault)
			return
		}
		s.writeError(w, 405, 1005, "method not allowed")
		return
	}
	nsid := pathUnescape(p[0])
	idx := -1
	for i := range s.namespaces {
		if s.namespaces[i].ID == nsid {
			idx = i
			break
		}
	}
	if idx < 0 {
		s.writeError(w, 404, 10004, "KV namespace not found")
		return
	}
	if len(p) == 1 {
		if r.Method == http.MethodDelete {
			delete(s.kv, nsid)
			s.namespaces = append(s.namespaces[:idx], s.namespaces[idx+1:]...)
			s.writeMutation(r, w, body, 200, nil, nil, fault)
			return
		}
		s.writeError(w, 405, 1005, "method not allowed")
		return
	}
	if p[1] == "bulk" {
		s.kvBulk(w, r, nsid, body, fault)
		return
	}
	if p[1] != "values" || len(p) != 3 {
		s.writeError(w, 404, 1000, "KV value not found")
		return
	}
	key := pathUnescape(p[2])
	values := s.kv[nsid]
	switch r.Method {
	case http.MethodGet:
		v, ok := values[key]
		if !ok {
			s.writeError(w, 404, 10004, "KV key not found")
			return
		}
		w.Header().Set("ETag", etag(string(v)))
		w.WriteHeader(200)
		_, _ = w.Write(v)
	case http.MethodPut:
		values[key] = append([]byte(nil), body...)
		w.Header().Set("ETag", etag(string(values[key])))
		s.writeMutation(r, w, body, 200, nil, nil, fault)
	case http.MethodDelete:
		delete(values, key)
		s.writeMutation(r, w, body, 200, nil, nil, fault)
	default:
		s.writeError(w, 405, 1005, "method not allowed")
	}
}

func (s *Server) kvBulk(w http.ResponseWriter, r *http.Request, nsid string, body []byte, fault FaultStep) {
	values := s.kv[nsid]
	if r.Method == http.MethodPut {
		var in []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		}
		if json.Unmarshal(body, &in) != nil {
			s.writeError(w, 400, 1003, "invalid KV bulk write")
			return
		}
		for _, v := range in {
			if v.Key != "" {
				values[v.Key] = []byte(v.Value)
			}
		}
		s.writeMutation(r, w, body, 200, nil, nil, fault)
		return
	}
	if r.Method == http.MethodDelete {
		var keys []string
		if json.Unmarshal(body, &keys) != nil {
			var obj struct {
				Keys []string `json:"keys"`
			}
			if json.Unmarshal(body, &obj) != nil {
				s.writeError(w, 400, 1003, "invalid KV bulk delete")
				return
			}
			keys = obj.Keys
		}
		for _, k := range keys {
			delete(values, k)
		}
		s.writeMutation(r, w, body, 200, nil, nil, fault)
		return
	}
	s.writeError(w, 405, 1005, "method not allowed")
}

func (s *Server) workerEndpoint(w http.ResponseWriter, r *http.Request, p []string, body []byte, fault FaultStep) {
	if len(p) == 0 {
		s.writeError(w, 404, 1000, "Worker script not found")
		return
	}
	scriptName := pathUnescape(p[0])
	s.mu.Lock()
	defer s.mu.Unlock()
	script := s.workers[scriptName]
	if script == nil {
		script = &workerScript{Versions: map[string]workerVersion{}, Deployments: map[string]workerDeployment{}}
		s.workers[scriptName] = script
	}
	if len(p) == 1 {
		if r.Method == http.MethodPut || r.Method == http.MethodPost {
			h := sha256.Sum256(body)
			v := workerVersion{ID: id("version", &s.nextID), Digest: hex.EncodeToString(h[:]), CreatedAt: time.Now().UTC()}
			script.Versions[v.ID] = v
			script.Active = v.ID
			s.writeMutation(r, w, body, 200, v, nil, fault)
			return
		}
		if r.Method == http.MethodGet {
			if script.Active == "" {
				s.writeError(w, 404, 10004, "active Worker version not found")
				return
			}
			s.envelope(w, 200, script.Versions[script.Active], nil)
			return
		}
		s.writeError(w, 404, 1000, "Worker resource not found")
		return
	}
	if p[1] != "versions" && p[1] != "deployments" {
		s.writeError(w, 404, 1000, "Worker resource not found")
		return
	}
	if p[1] == "versions" {
		if len(p) == 2 && r.Method == http.MethodGet {
			out := make([]workerVersion, 0, len(script.Versions))
			for _, v := range script.Versions {
				out = append(out, v)
			}
			sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
			start, end, number, total := page(r, len(out))
			per := end - start
			if per == 0 {
				per = 20
			}
			s.listEnvelope(w, 200, out[start:end], resultInfo(number, per, total))
			return
		}
		if len(p) == 2 && r.Method == http.MethodPost {
			var in struct {
				Digest   string          `json:"digest"`
				Metadata json.RawMessage `json:"metadata"`
			}
			_ = json.Unmarshal(body, &in)
			if in.Digest == "" {
				h := sha256.Sum256(body)
				in.Digest = hex.EncodeToString(h[:])
			}
			v := workerVersion{ID: id("version", &s.nextID), Digest: in.Digest, Metadata: in.Metadata, CreatedAt: time.Now().UTC()}
			script.Versions[v.ID] = v
			result := map[string]any{"id": v.ID, "digest": v.Digest}
			if s.cfg.AsyncPolls > 0 {
				op := s.newOperation(result)
				s.writeMutation(r, w, body, http.StatusAccepted, op, nil, fault)
			} else {
				s.writeMutation(r, w, body, 200, v, nil, fault)
			}
			return
		}
		if len(p) == 3 && r.Method == http.MethodGet {
			v, ok := script.Versions[pathUnescape(p[2])]
			if !ok {
				s.writeError(w, 404, 10004, "Worker version not found")
				return
			}
			s.envelope(w, 200, v, nil)
			return
		}
		s.writeError(w, 405, 1005, "method not allowed")
		return
	}
	if len(p) == 2 && r.Method == http.MethodGet {
		out := make([]workerDeployment, 0, len(script.Deployments))
		for _, d := range script.Deployments {
			out = append(out, d)
		}
		sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
		start, end, number, total := page(r, len(out))
		per := end - start
		if per == 0 {
			per = 20
		}
		s.listEnvelope(w, 200, out[start:end], resultInfo(number, per, total))
		return
	}
	if len(p) == 2 && (r.Method == http.MethodPost || r.Method == http.MethodPut) {
		var in struct {
			ID         string              `json:"id"`
			Versions   []deploymentVersion `json:"versions"`
			VersionID  string              `json:"version_id"`
			Percentage int                 `json:"percentage"`
		}
		if json.Unmarshal(body, &in) != nil {
			s.writeError(w, 400, 1003, "invalid Worker deployment")
			return
		}
		if len(in.Versions) == 0 && in.VersionID != "" {
			in.Versions = []deploymentVersion{{VersionID: in.VersionID, Percentage: in.Percentage}}
		}
		for _, v := range in.Versions {
			if _, ok := script.Versions[v.VersionID]; !ok {
				s.writeError(w, 404, 10004, "Worker version not found")
				return
			}
		}
		d := workerDeployment{ID: in.ID, Versions: in.Versions, Status: "active"}
		if d.ID == "" {
			d.ID = id("deployment", &s.nextID)
		}
		script.Deployments[d.ID] = d
		if len(in.Versions) == 1 && in.Versions[0].Percentage >= 100 {
			script.Active = in.Versions[0].VersionID
		}
		if s.cfg.AsyncPolls > 0 {
			op := s.newOperation(d)
			s.writeMutation(r, w, body, 202, op, nil, fault)
		} else {
			s.writeMutation(r, w, body, 200, d, nil, fault)
		}
		return
	}
	if len(p) == 3 && r.Method == http.MethodGet {
		d, ok := script.Deployments[pathUnescape(p[2])]
		if !ok {
			s.writeError(w, 404, 10004, "Worker deployment not found")
			return
		}
		s.envelope(w, 200, d, nil)
		return
	}
	s.writeError(w, 405, 1005, "method not allowed")
}

func (s *Server) newOperation(result any) *operation {
	o := &operation{ID: id("op", &s.nextID), Status: "pending", Polls: s.cfg.AsyncPolls, Result: result}
	s.ops[o.ID] = o
	return o
}
func (s *Server) operation(w http.ResponseWriter, r *http.Request, opid string) {
	if r.Method != http.MethodGet {
		s.writeError(w, 405, 1005, "method not allowed")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.ops[pathUnescape(opid)]
	if !ok {
		s.writeError(w, 404, 10004, "operation not found")
		return
	}
	if o.Polls > 0 {
		o.Polls--
	}
	if o.Polls <= 0 {
		o.Status = "complete"
	}
	if o.Status == "failed" {
		s.writeError(w, 500, 1007, o.Err)
		return
	}
	status := http.StatusOK
	if o.Status != "complete" {
		status = http.StatusAccepted
	}
	s.envelope(w, status, map[string]any{"id": o.ID, "status": o.Status, "result": o.Result}, nil)
}

func (s *Server) secretEndpoint(w http.ResponseWriter, r *http.Request, p []string, body []byte, fault FaultStep) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(p) == 1 && p[0] == "stores" {
		if r.Method == http.MethodGet {
			names := make([]string, 0, len(s.secrets))
			for n := range s.secrets {
				names = append(names, n)
			}
			sort.Strings(names)
			out := make([]map[string]any, 0, len(names))
			for _, n := range names {
				out = append(out, map[string]any{"id": n, "name": n})
			}
			s.envelope(w, 200, out, nil)
			return
		}
		if r.Method == http.MethodPost {
			var in struct {
				Name string `json:"name"`
			}
			if json.Unmarshal(body, &in) != nil || in.Name == "" {
				s.writeError(w, 400, 1003, "invalid secret store")
				return
			}
			if s.secrets[in.Name] != nil {
				s.writeError(w, 409, 1006, "secret store exists")
				return
			}
			s.secrets[in.Name] = map[string]secret{}
			s.writeMutation(r, w, body, 200, map[string]string{"id": in.Name, "name": in.Name}, nil, fault)
			return
		}
	}
	if len(p) < 2 || p[0] != "stores" {
		s.writeError(w, 404, 1000, "secret store not found")
		return
	}
	store := pathUnescape(p[1])
	if s.secrets[store] == nil {
		s.writeError(w, 404, 10004, "secret store not found")
		return
	}
	if len(p) == 2 && r.Method == http.MethodGet {
		out := make([]map[string]any, 0, len(s.secrets[store]))
		for n, v := range s.secrets[store] {
			out = append(out, map[string]any{"name": n, "version": v.Version, "updated_at": v.UpdatedAt})
		}
		sort.Slice(out, func(i, j int) bool { return out[i]["name"].(string) < out[j]["name"].(string) })
		s.envelope(w, 200, out, nil)
		return
	}
	if len(p) == 2 && r.Method == http.MethodDelete {
		delete(s.secrets, store)
		s.writeMutation(r, w, body, 200, nil, nil, fault)
		return
	}
	if len(p) == 3 && p[2] == "secrets" && (r.Method == http.MethodPost || r.Method == http.MethodPut) {
		var in struct {
			Name        string `json:"name"`
			Value       string `json:"value"`
			ValueBase64 string `json:"value_base64"`
		}
		if json.Unmarshal(body, &in) != nil || in.Name == "" {
			s.writeError(w, 400, 1003, "invalid secret")
			return
		}
		value := []byte(in.Value)
		if in.ValueBase64 != "" {
			value, _ = base64.StdEncoding.DecodeString(in.ValueBase64)
		}
		v := s.secrets[store][in.Name]
		v.Name, v.Value, v.Version, v.UpdatedAt = in.Name, append([]byte(nil), value...), v.Version+1, time.Now().UTC()
		s.secrets[store][in.Name] = v
		s.writeMutation(r, w, body, 200, map[string]any{"name": in.Name, "version": v.Version, "updated_at": v.UpdatedAt}, nil, fault)
		return
	}
	nameIndex := 2
	if len(p) > 2 && p[2] == "secrets" {
		nameIndex = 3
	}
	// Cloudflare's rotation form appends /versions to a named secret. The
	// response intentionally contains metadata only; secret bytes never leave
	// this process.
	rotation := len(p) == 5 && p[2] == "secrets" && p[4] == "versions"
	if rotation {
		nameIndex = 3
	}
	if rotation && r.Method != http.MethodPost {
		s.writeError(w, 405, 1005, "method not allowed")
		return
	}
	if rotation {
		name := pathUnescape(p[nameIndex])
		var in struct {
			Value       string `json:"value"`
			ValueBase64 string `json:"value_base64"`
		}
		if json.Unmarshal(body, &in) != nil {
			s.writeError(w, 400, 1003, "invalid secret")
			return
		}
		value := []byte(in.Value)
		if in.ValueBase64 != "" {
			value, _ = base64.StdEncoding.DecodeString(in.ValueBase64)
		}
		v := s.secrets[store][name]
		v.Name, v.Value, v.Version, v.UpdatedAt = name, append([]byte(nil), value...), v.Version+1, time.Now().UTC()
		s.secrets[store][name] = v
		s.writeMutation(r, w, body, 200, map[string]any{"name": name, "version": v.Version, "updated_at": v.UpdatedAt}, nil, fault)
		return
	}
	if len(p) != nameIndex+1 {
		s.writeError(w, 404, 1000, "secret not found")
		return
	}
	name := pathUnescape(p[nameIndex])
	if r.Method == http.MethodGet {
		v, ok := s.secrets[store][name]
		if !ok {
			s.writeError(w, 404, 10004, "secret not found")
			return
		}
		s.envelope(w, 200, map[string]any{"name": name, "version": v.Version, "updated_at": v.UpdatedAt}, nil)
		return
	}
	if r.Method == http.MethodDelete {
		delete(s.secrets[store], name)
		s.writeMutation(r, w, body, 200, nil, nil, fault)
		return
	}
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		var in struct {
			Name        string `json:"name"`
			Value       string `json:"value"`
			ValueBase64 string `json:"value_base64"`
		}
		if json.Unmarshal(body, &in) != nil {
			s.writeError(w, 400, 1003, "invalid secret")
			return
		}
		if in.Name != "" {
			name = in.Name
		}
		value := []byte(in.Value)
		if in.ValueBase64 != "" {
			value, _ = base64.StdEncoding.DecodeString(in.ValueBase64)
		}
		old := s.secrets[store][name]
		old.Name = name
		old.Value = append([]byte(nil), value...)
		old.Version++
		old.UpdatedAt = time.Now().UTC()
		s.secrets[store][name] = old
		s.writeMutation(r, w, body, 200, map[string]any{"name": name, "version": old.Version, "updated_at": old.UpdatedAt}, nil, fault)
		return
	}
	s.writeError(w, 405, 1005, "method not allowed")
}
