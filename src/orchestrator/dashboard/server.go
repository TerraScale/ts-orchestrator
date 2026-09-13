package dashboard

import (
	"bytes"
	"embed"
	"encoding/json/v2"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"
)

//go:embed web/*
var webFiles embed.FS

type pageSpec struct{ Path, Key, Title, Description string }

var pages = [...]pageSpec{
	{Path: "/", Key: "overview", Title: "Global control plane", Description: "Authority, estate health, and current work."},
	{Path: "/regions", Key: "regions", Title: "Regional estate", Description: "Placement, capacity, latency, and health by region."},
	{Path: "/nodes", Key: "nodes", Title: "Host fleet", Description: "Every member and worker observed by the orchestrator."},
	{Path: "/events", Key: "events", Title: "Control-plane activity", Description: "Reconciliation and health signals, newest first."},
	{Path: "/terrabase", Key: "terrabase", Title: "TerraBase fabric", Description: "Replication, storage, and provider boundaries."},
	{Path: "/delivery", Key: "delivery", Title: "Release delivery", Description: "Canary, rollout, drain, and rollback observations."},
}

// PageView is the complete server-side view model. Templates should render this
// model directly; JavaScript is reserved for charts and live fragment updates.
type PageView struct {
	Page                            pageViewMeta
	Path, Query, Region, ActivePath string
	State                           State
	StateJSON                       template.JS
	Regions                         []Region
	Nodes                           []Node
	Events                          []Event
	PageNumber, PageCount, Total    int
	Navigation                      []navItem
}
type pageViewMeta struct{ Key, Title, Description, Kicker string }
type navItem struct {
	Href, Label, Glyph string
	Active             bool
}

type Server struct {
	store   *Store
	handler http.Handler
	tmpl    *template.Template
	pages   map[string]*template.Template
}

func NewServer(store *Store) *Server {
	assets, _ := fs.Sub(webFiles, "web")
	funcs := template.FuncMap{
		"time": func(v time.Time) string {
			if v.IsZero() {
				return "UNAVAILABLE"
			}
			return v.UTC().Format("2006-01-02 15:04:05 UTC")
		},
		"statusClass": func(v string) string {
			v = strings.ToLower(strings.TrimSpace(v))
			if v == "" {
				return "unknown"
			}
			return v
		},
		"percent": func(v float64) string { return strconv.FormatFloat(max(0, min(100, v)), 'f', 0, 64) + "%" },
		"decimal": func(v float64) string { return strconv.FormatFloat(v, 'f', 1, 64) },
		"bytes": func(v uint64) string {
			if v >= 1<<30 {
				return fmt.Sprintf("%.1f GB", float64(v)/(1<<30))
			}
			if v >= 1<<20 {
				return fmt.Sprintf("%.1f MB", float64(v)/(1<<20))
			}
			if v >= 1<<10 {
				return fmt.Sprintf("%.1f KB", float64(v)/(1<<10))
			}
			return fmt.Sprintf("%d B", v)
		},
		"json": func(v any) template.JS { b, _ := json.Marshal(v); return template.JS(b) },
		"mapX": func(v float64) float64 { return (v+180)/360*94 + 3 }, "mapY": func(v float64) float64 { return (90-v)/180*82 + 9 },
		"take": func(n int, xs []Event) []Event {
			if n > len(xs) {
				n = len(xs)
			}
			return xs[:n]
		},
	}
	t, err := template.New("layout.html").Funcs(funcs).ParseFS(assets, "templates/layout.html")
	if err != nil {
		panic(fmt.Sprintf("dashboard template: %v", err))
	}
	// Each page owns the shared "content" definition. Parse it per request
	// below so templates cannot accidentally render another page's body.
	s := &Server{store: store, tmpl: t, pages: make(map[string]*template.Template, len(pages))}
	for _, spec := range pages {
		pageTemplate, parseErr := t.Clone()
		if parseErr == nil {
			pageTemplate, parseErr = pageTemplate.ParseFS(assets, "templates/"+spec.Key+".html")
		}
		if parseErr != nil {
			panic(fmt.Sprintf("dashboard %s template: %v", spec.Key, parseErr))
		}
		s.pages[spec.Key] = pageTemplate
	}
	mux := http.NewServeMux()
	for _, spec := range pages {
		sp := spec
		mux.HandleFunc("GET "+sp.Path, func(w http.ResponseWriter, r *http.Request) { s.page(w, r, sp) })
	}
	fileServer := http.FileServer(http.FS(assets))
	for _, path := range []string{"/style.css", "/app.js", "/vendor/", "/fonts/"} {
		mux.Handle("GET "+path, fileServer)
	}
	mux.HandleFunc("GET /api/state", store.stateHandler)
	mux.HandleFunc("GET /api/events", store.events)
	mux.HandleFunc("GET /api/stream", s.stream)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	// ServeMux treats the root pattern as a subtree. Guard the outer handler so
	// unknown paths are explicit 404s instead of silently rendering overview.
	s.handler = securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !knownDashboardPath(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	return s
}

func knownDashboardPath(path string) bool {
	for _, p := range pages {
		if path == p.Path {
			return true
		}
	}
	if path == "/style.css" || path == "/app.js" || path == "/api/state" || path == "/api/events" || path == "/api/stream" || path == "/healthz" {
		return true
	}
	return strings.HasPrefix(path, "/vendor/") || strings.HasPrefix(path, "/fonts/")
}
func (s *Server) page(w http.ResponseWriter, r *http.Request, spec pageSpec) {
	v := makeView(spec, s.store.Snapshot(), r)
	var out bytes.Buffer
	t := s.pages[spec.Key]
	if err := t.ExecuteTemplate(&out, "layout", v); err != nil {
		http.Error(w, "page unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(out.Bytes())
}
func makeView(spec pageSpec, state State, r *http.Request) PageView {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	region := strings.TrimSpace(r.URL.Query().Get("region"))
	regions := filterRegions(state.Regions, q)
	nodes := filterNodes(state.Nodes, q, region)
	events := filterEvents(state.Events, q, region)
	pn, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if pn < 1 {
		pn = 1
	}
	per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if per < 1 || per > 200 {
		per = 50
	}
	total := len(events)
	count := max(1, (total+per-1)/per)
	if pn > count {
		pn = count
	}
	start := min((pn-1)*per, total)
	end := min(start+per, total)
	events = events[start:end]
	b, _ := json.Marshal(state)
	nav := make([]navItem, 0, len(pages))
	icons := map[string]string{"overview": "layout-dashboard", "regions": "globe-2", "nodes": "server", "events": "activity", "terrabase": "database", "delivery": "rocket"}
	for _, p := range pages {
		nav = append(nav, navItem{Href: p.Path, Label: p.Title, Glyph: icons[p.Key], Active: p.Path == spec.Path})
	}
	return PageView{Page: pageViewMeta{Key: spec.Key, Title: spec.Title, Description: spec.Description, Kicker: "ORCHESTRATOR OBSERVABILITY"}, Path: spec.Path, Query: q, Region: region, ActivePath: spec.Path, State: state, StateJSON: template.JS(b), Regions: regions, Nodes: nodes, Events: events, PageNumber: pn, PageCount: count, Total: total, Navigation: nav}
}
func filterRegions(in []Region, q string) []Region {
	if q == "" {
		return in
	}
	out := make([]Region, 0, len(in))
	q = strings.ToLower(q)
	for _, x := range in {
		if strings.Contains(strings.ToLower(x.Code+" "+x.OCIName+" "+x.Health), q) {
			out = append(out, x)
		}
	}
	return out
}
func filterNodes(in []Node, q, region string) []Node {
	out := make([]Node, 0, len(in))
	q, region = strings.ToLower(q), strings.ToLower(region)
	for _, x := range in {
		text := strings.ToLower(x.ID + " " + x.Address + " " + x.Role + " " + x.Status + " " + x.Version)
		if (q == "" || strings.Contains(text, q)) && (region == "" || strings.EqualFold(x.Region, region)) {
			out = append(out, x)
		}
	}
	return out
}
func filterEvents(in []Event, q, region string) []Event {
	out := make([]Event, 0, len(in))
	q, region = strings.ToLower(q), strings.ToLower(region)
	for _, x := range in {
		text := strings.ToLower(x.Level + " " + x.Kind + " " + x.Region + " " + x.Node + " " + x.Message)
		if (q == "" || strings.Contains(text, q)) && (region == "" || strings.EqualFold(x.Region, region)) {
			out = append(out, x)
		}
	}
	return out
}
func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	spec := pages[0]
	requestedPath := r.URL.Query().Get("path")
	if requestedPath == "" {
		requestedPath = r.URL.Path
	}
	for _, p := range pages {
		if p.Path == requestedPath || p.Key == requestedPath {
			spec = p
			break
		}
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	last := uint64(^uint64(0))
	for state := range s.store.Subscribe(r.Context()) {
		if state.Version == last {
			continue
		}
		last = state.Version
		v := makeView(spec, state, r)
		var out bytes.Buffer
		t := s.pages[spec.Key]
		if err := t.ExecuteTemplate(&out, "layout", v); err != nil {
			return
		}
		fragment := extractMain(out.String())
		if _, err := fmt.Fprintf(w, "event: datastar-merge-fragments\ndata: fragments <main id=page-content>%s</main>\n\n", fragment); err != nil {
			return
		}
		flusher.Flush()
	}
}
func extractMain(s string) string {
	marker := `<main id="page-content"`
	start := strings.Index(s, marker)
	if start >= 0 {
		if endTag := strings.Index(s[start:], ">"); endTag >= 0 {
			start += endTag + 1
		} else {
			return s
		}
	} else {
		marker = `<main class="page-shell">`
		start = strings.Index(s, marker)
		if start >= 0 {
			start += len(marker)
		}
	}
	if start < 0 {
		return s
	}
	end := strings.Index(s[start:], `</main>`)
	if end < 0 {
		return s[start:]
	}
	return s[start : start+end]
}
func (s *Server) Handler() http.Handler { return s.handler }
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-eval'; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}
func (s *Store) stateHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	payload, err := json.Marshal(s.Snapshot())
	if err != nil {
		http.Error(w, "state unavailable", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(payload)
}
func (s *Store) events(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	for state := range s.Subscribe(r.Context()) {
		payload, err := json.Marshal(state)
		if err != nil {
			return
		}
		if _, err = fmt.Fprintf(w, "event: state\ndata: %s\n\n", payload); err != nil {
			return
		}
		flusher.Flush()
	}
}
