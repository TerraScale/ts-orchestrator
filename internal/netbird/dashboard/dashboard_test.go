package dashboard

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func archive(t *testing.T, name string, kind byte) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	entries := map[string]string{
		"index.html":                 "<html>NetBird dashboard</html>",
		"peers.html":                 "<html>Peers</html>",
		"peers.txt":                  "next route data",
		"OidcTrustedDomains.js.tmpl": `const trustedDomains={default:["$NETBIRD_MGMT_API_ENDPOINT"]};`,
		"_next/static/config.js":     `const config={scopes:"$AUTH_SUPPORTED_SCOPES",authority:"$AUTH_AUTHORITY",client:"$AUTH_CLIENT_ID",auth0:"$USE_AUTH0",redirect:"$AUTH_REDIRECT_URI",silent:"$AUTH_SILENT_REDIRECT_URI",cloud:"$NETBIRD_CLOUD"}; const unrelated="$D";`,
	}
	for name, body := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: "usr/share/nginx/html/" + name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if name != "" {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: kind, Linkname: "/etc/passwd", Size: 0}); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestExportServesOIDCCallbacksAndNextRoutes(t *testing.T) {
	site, err := unpack(archive(t, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	config := string(site["/_next/static/config.js"])
	for _, want := range []string{"https://netbird.terrascale.tech/oauth2", "netbird-dashboard", "openid profile email groups", "/nb-auth", "/nb-silent-auth", `auth0:"false"`, `cloud:"false"`, `unrelated="$D"`} {
		if !strings.Contains(config, want) {
			t.Errorf("config missing %q: %s", want, config)
		}
	}
	if strings.Contains(config, "$AUTH_") || strings.Contains(config, "$NETBIRD_") {
		t.Fatal("unexpanded upstream configuration")
	}
	if strings.Contains(string(site["/OidcTrustedDomains.js"]), "$NETBIRD_") {
		t.Fatal("trusted domains not configured")
	}
	h := New(t.TempDir())
	h.site.Store(&site)
	for _, target := range []string{"/", "/peers", "/peers.html", "/peers.txt?_rsc=query", "/nb-auth?code=opaque&state=opaque", "/nb-silent-auth", "/_next/static/config.js"} {
		t.Run(target, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
			if w.Code != 200 {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if w.Header().Get("X-Frame-Options") != "SAMEORIGIN" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'self'") {
				t.Fatal("silent callback framing denied")
			}
		})
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodHead, "/", nil))
	if w.Code != 200 || w.Body.Len() != 0 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("HEAD response: %#v %s", w.Result(), w.Body.String())
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/missing.js", nil))
	if w.Code != 404 {
		t.Fatal("missing assets must not serve HTML")
	}
}

func TestUnsafeOrIncompleteLayerRejected(t *testing.T) {
	for _, test := range []struct {
		name string
		kind byte
	}{
		{"usr/share/nginx/html/../../outside", tar.TypeReg},
		{"usr/share/nginx/html/absolute", tar.TypeSymlink},
		{"etc/passwd", tar.TypeReg},
	} {
		if _, err := unpack(archive(t, test.name, test.kind)); err == nil {
			t.Fatalf("accepted %s", test.name)
		}
	}
	if _, err := unpack([]byte("not gzip")); err == nil {
		t.Fatal("accepted invalid archive")
	}
	if err := verify(archive(t, "", 0)); err == nil {
		t.Fatal("accepted an unpinned archive")
	}
}

func TestUnpreparedDashboardRequestsRetry(t *testing.T) {
	h := New(t.TempDir())
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != 503 || w.Header().Get("Retry-After") != "15" {
		t.Fatal("initial provisioning should request retry")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", nil))
	if w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD" {
		t.Fatal("static site accepted a write")
	}
}
