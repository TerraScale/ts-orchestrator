// Package dashboard serves the pinned upstream NetBird web admin application.
// The edge owns its lifecycle; no container, listener or writable image is needed.
package dashboard

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// v2.94.0 arm64 image manifest:
// sha256:44a250c04d91b46aa666de4b2b25602f0580b64dee0682fedfb9d012cb020ff7.
// Its final COPY out/ layer is architecture-independent static content.
const layerSHA256 = "39224d252d48fc481e9107bf1a22171c2ef0268f44def5cda41e9ecdd82bbde6"
const layerBytes = 8917025
const maxExpandedBytes = 64 << 20

type files map[string][]byte

// Handler retains the verified site in memory so cache damage or a temporary
// registry outage never interrupts a site already serving.
type Handler struct {
	cache string
	site  atomic.Pointer[files]
}

func New(stateDir string) *Handler {
	return &Handler{cache: filepath.Join(stateDir, "netbird-dashboard", layerSHA256+".tar.gz")}
}

// Reconcile repairs missing or damaged cache material and publishes the complete
// site atomically. The digest in the binary selects the upgrade on every host.
func (h *Handler) Reconcile(ctx context.Context) error {
	layer, err := readCache(h.cache)
	if err != nil || verify(layer) != nil {
		layer, err = download(ctx)
		if err != nil {
			return err
		}
		if err := verify(layer); err != nil {
			return err
		}
		if err := save(h.cache, layer); err != nil {
			return err
		}
	}
	if h.site.Load() != nil {
		return nil
	}
	site, err := unpack(layer)
	if err != nil {
		return err
	}
	h.site.Store(&site)
	return nil
}

func readCache(name string) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, layerBytes+1))
}

func verify(layer []byte) error {
	sum := sha256.Sum256(layer)
	if len(layer) != layerBytes || hex.EncodeToString(sum[:]) != layerSHA256 {
		return errors.New("NetBird dashboard static layer checksum mismatch")
	}
	return nil
}

func download(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	client := &http.Client{Timeout: 2 * time.Minute}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://auth.docker.io/token?service=registry.docker.io&scope=repository:netbirdio/dashboard:pull", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("NetBird dashboard registry authentication unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NetBird dashboard registry authentication status %d", resp.StatusCode)
	}
	var auth struct {
		Token string `json:"token"`
	}
	if err := json.UnmarshalRead(io.LimitReader(resp.Body, 64<<10), &auth); err != nil || auth.Token == "" {
		return nil, errors.New("NetBird dashboard registry authentication invalid")
	}
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, "https://registry-1.docker.io/v2/netbirdio/dashboard/blobs/sha256:"+layerSHA256, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+auth.Token)
	resp, err = client.Do(req)
	if err != nil {
		return nil, errors.New("NetBird dashboard static layer download unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NetBird dashboard static layer status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, layerBytes+1))
}

func save(name string, body []byte) error {
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(name), ".dashboard-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(body); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), name)
}

func unpack(layer []byte) (files, error) {
	gz, err := gzip.NewReader(bytes.NewReader(layer))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, maxExpandedBytes+1))
	site := make(files)
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		const prefix = "usr/share/nginx/html/"
		if hdr.Typeflag != tar.TypeReg || !strings.HasPrefix(hdr.Name, prefix) {
			return nil, errors.New("NetBird dashboard static layer contains a non-site file")
		}
		name := strings.TrimPrefix(hdr.Name, prefix)
		if name == "" || path.Clean(name) != name || strings.HasPrefix(name, "../") || strings.HasPrefix(name, "/") {
			return nil, errors.New("NetBird dashboard static layer contains an unsafe path")
		}
		total += hdr.Size
		if hdr.Size < 0 || hdr.Size > 8<<20 || total > maxExpandedBytes || len(site) >= 4096 {
			return nil, errors.New("NetBird dashboard static layer exceeds site limits")
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		if bytes.Contains(body, []byte("AUTH_SUPPORTED_SCOPES")) || name == "OidcTrustedDomains.js.tmpl" {
			body = []byte(substitute(string(body)))
		}
		if name == "OidcTrustedDomains.js.tmpl" {
			name = "OidcTrustedDomains.js"
		}
		site["/"+name] = body
	}
	if len(site["/index.html"]) == 0 || len(site["/peers.html"]) == 0 || len(site["/OidcTrustedDomains.js"]) == 0 {
		return nil, errors.New("NetBird dashboard static layer lacks application entrypoints")
	}
	return site, nil
}

// Substitute only upstream environment names. os.Expand would also consume
// unrelated dollar expressions in the compiled JavaScript.
func substitute(body string) string {
	const origin = "https://netbird.terrascale.tech"
	values := map[string]string{
		"USE_AUTH0": "false", "AUTH_AUDIENCE": "netbird-dashboard", "AUTH_CLIENT_ID": "netbird-dashboard",
		"AUTH_CLIENT_SECRET": "", "AUTH_AUTHORITY": origin + "/oauth2", "AUTH_SUPPORTED_SCOPES": "openid profile email groups",
		"AUTH_REDIRECT_URI": "/nb-auth", "AUTH_SILENT_REDIRECT_URI": "/nb-silent-auth",
		"NETBIRD_MGMT_API_ENDPOINT": origin, "NETBIRD_MGMT_GRPC_API_ENDPOINT": origin,
		"NETBIRD_TOKEN_SOURCE": "accessToken", "NETBIRD_DRAG_QUERY_PARAMS": "false",
		// Fixed third-party dashboard fields select the upstream self-hosted UI.
		"NETBIRD_LICENSED": "false", "NETBIRD_CLOUD": "false", "NETBIRD_AGENT_NETWORK_ONLY": "false", "NETBIRD_AGENT_NETWORK_ENABLED": "false",
	}
	// These upstream integration fields deliberately have no vendor configuration.
	for _, name := range []string{"NETBIRD_HOTJAR_TRACK_ID", "NETBIRD_GOOGLE_ANALYTICS_ID", "NETBIRD_GOOGLE_TAG_MANAGER_ID", "NETBIRD_AUTH_SERVICE_URL", "NETBIRD_WASM_PATH", "NETBIRD_HUBSPOT_PORTAL_ID", "NETBIRD_HUBSPOT_SIGNUP_FORM_ID", "NETBIRD_HUBSPOT_ONBOARDING_FORM_ID", "NETBIRD_HUBSPOT_SURVEY_FORM_ID", "NETBIRD_ANALYTICS_EXCLUDED_EMAILS", "NETBIRD_ANNOUNCEMENT"} {
		values[name] = ""
	}
	var pairs []string
	for name, value := range values {
		pairs = append(pairs, "${"+name+"}", value, "$"+name, value)
	}
	return strings.NewReplacer(pairs...).Replace(body)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'self'; base-uri 'self'; object-src 'none'")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	site := h.site.Load()
	if site == nil {
		w.Header().Set("Retry-After", "15")
		http.Error(w, "NetBird dashboard is preparing", http.StatusServiceUnavailable)
		return
	}
	name := path.Clean("/" + r.URL.Path)
	if name == "/" || name == "/nb-auth" || name == "/nb-silent-auth" {
		name = "/index.html"
	}
	body, ok := (*site)[name]
	if !ok && path.Ext(name) == "" {
		name += ".html"
		body, ok = (*site)[name]
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	if contentType := mime.TypeByExtension(path.Ext(name)); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(body))
}
