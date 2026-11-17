package oraclehost

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	githubAPI        = "api.github.com"
	githubWeb        = "github.com"
	githubAssets     = "release-assets.githubusercontent.com"
	githubRepository = "TerraScale/ts-orchestrator"
	githubPageSize   = 30
)

type GitHub struct {
	mu          sync.Mutex
	recorded    []map[string]any
	published   []map[string]any
	downloads   map[string]string
	assets      map[string][]byte
	comparisons map[string][]byte
	version     int
	requests    []string
}

func newGitHub() *GitHub {
	return &GitHub{downloads: map[string]string{}, assets: map[string][]byte{}, comparisons: map[string][]byte{}}
}

func (f *Fleet) GitHub() *GitHub { return f.standIn.github }

func ComparisonKey(base, head string, page int) string {
	return fmt.Sprintf("%s...%s?page=%d", base, head, page)
}

func (g *GitHub) Record(releases []byte, comparisons map[string][]byte) error {
	var recorded []map[string]any
	if err := json.Unmarshal(releases, &recorded); err != nil {
		return fmt.Errorf("recorded GitHub releases: %w", err)
	}
	if len(recorded) == 0 {
		return fmt.Errorf("recorded GitHub releases are empty")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.recorded, g.comparisons = recorded, comparisons
	return nil
}

func (g *GitHub) Publish(tag string, files map[string][]byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	template := g.recorded[0]
	assetTemplate := map[string]any{}
	if assets, ok := template["assets"].([]any); ok && len(assets) != 0 {
		assetTemplate, _ = assets[0].(map[string]any)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	release := map[string]any{}
	for key, value := range template {
		release[key] = value
	}
	id := 900000000 + len(g.published)
	release["id"], release["tag_name"], release["name"] = id, tag, tag
	release["draft"], release["prerelease"] = false, true
	release["created_at"], release["published_at"] = now, now
	release["html_url"] = "https://" + githubWeb + "/" + githubRepository + "/releases/tag/" + tag
	assets := []any{}
	for name, data := range files {
		sum := sha256.Sum256(data)
		asset := map[string]any{}
		for key, value := range assetTemplate {
			asset[key] = value
		}
		assetID := strconv.Itoa(id) + "-" + strconv.Itoa(len(g.assets))
		download := "/" + githubRepository + "/releases/download/" + tag + "/" + name
		asset["id"], asset["name"], asset["label"] = assetID, name, ""
		asset["state"], asset["size"], asset["digest"] = "uploaded", len(data), fmt.Sprintf("sha256:%x", sum)
		asset["created_at"], asset["updated_at"] = now, now
		asset["browser_download_url"] = "https://" + githubWeb + download
		g.downloads[download] = "/github-production-release-asset/" + assetID
		g.assets["/github-production-release-asset/"+assetID] = data
		assets = append(assets, asset)
	}
	release["assets"] = assets
	g.published = append([]map[string]any{release}, g.published...)
	g.version++
}

func (g *GitHub) Requests() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.requests...)
}

func (g *GitHub) serve(w http.ResponseWriter, r *http.Request, host string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	status := g.answer(w, r, host)
	g.requests = append(g.requests, fmt.Sprintf("%d %s %s%s", status, r.Method, host, r.URL.RequestURI()))
}

func (g *GitHub) answer(w http.ResponseWriter, r *http.Request, host string) int {
	repository := "/repos/" + githubRepository
	if r.Method != http.MethodGet {
		return githubError(w, http.StatusNotFound)
	}
	switch {
	case host == githubAPI && r.URL.Path == repository+"/releases":
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
		etag := fmt.Sprintf(`W/"%d"`, g.version)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return http.StatusNotModified
		}
		releases := []map[string]any{}
		if len(g.published) != 0 {
			releases = append(append(releases, g.published...), g.recorded...)
		}
		w.Header().Set("ETag", etag)
		writeJSON(w, http.StatusOK, releases[:min(len(releases), githubPageSize)])
		return http.StatusOK
	case host == githubAPI && strings.HasPrefix(r.URL.Path, repository+"/compare/"):
		page, err := strconv.Atoi(r.URL.Query().Get("page"))
		base, head, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, repository+"/compare/"), "...")
		body, ok := g.comparisons[ComparisonKey(base, head, page)]
		if err != nil || !ok || r.URL.Query().Get("per_page") != "1" {
			return githubError(w, http.StatusNotFound)
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(body)
		return http.StatusOK
	case host == githubWeb && g.downloads[r.URL.Path] != "":
		http.Redirect(w, r, "https://"+githubAssets+g.downloads[r.URL.Path], http.StatusFound)
		return http.StatusFound
	case host == githubAssets && g.assets[r.URL.Path] != nil:
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(g.assets[r.URL.Path])
		return http.StatusOK
	}
	return githubError(w, http.StatusNotFound)
}

func githubError(w http.ResponseWriter, status int) int {
	writeJSON(w, status, map[string]string{"message": http.StatusText(status), "documentation_url": "https://docs.github.com/rest"})
	return status
}
