package dashboard

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

// The vendored client files are pinned copies served from the binary; no page
// loads anything from a CDN:
//
//   - pico.min.css: Pico CSS v2.1.1 (MIT), css/pico.min.css of the release.
//   - datastar.js: Datastar v1.0.4 (MIT), bundles/datastar.js of the release.
//   - dashboard.css: this slice's density overrides and status colors.
//
//go:embed assets/*.css assets/*.js
var assetFiles embed.FS

// asset is one embedded file addressed by its content hash, so a response can
// be cached forever and a new binary changes every URL whose content changed.
type asset struct {
	body        []byte
	hash        string
	contentType string
}

var assets = loadAssets()

func loadAssets() map[string]asset {
	loaded := map[string]asset{}
	entries, err := fs.ReadDir(assetFiles, "assets")
	if err != nil {
		panic(err)
	}
	for _, entry := range entries {
		body, err := assetFiles.ReadFile("assets/" + entry.Name())
		if err != nil {
			panic(err)
		}
		sum := sha256.Sum256(body)
		contentType := mime.TypeByExtension(path.Ext(entry.Name()))
		if strings.HasSuffix(entry.Name(), ".js") {
			contentType = "text/javascript; charset=utf-8"
		}
		loaded[entry.Name()] = asset{body: body, hash: hex.EncodeToString(sum[:6]), contentType: contentType}
	}
	return loaded
}

// assetURL returns the content-addressed URL of an embedded file.
func assetURL(name string) string {
	file, ok := assets[name]
	if !ok {
		panic("dashboard asset " + name + " is not embedded")
	}
	return "/assets/" + file.hash + "/" + name
}

// serveAsset answers GET /assets/{hash}/{file}. A stale hash is a 404 rather
// than the current content, so an immutable cache never stores a mismatch.
func serveAsset(writer http.ResponseWriter, request *http.Request) {
	file, ok := assets[request.PathValue("file")]
	if !ok || request.PathValue("hash") != file.hash {
		http.NotFound(writer, request)
		return
	}
	etag := `"` + file.hash + `"`
	header := writer.Header()
	header.Set("ETag", etag)
	header.Set("Cache-Control", "public, max-age=31536000, immutable")
	header.Set("X-Content-Type-Options", "nosniff")
	if request.Header.Get("If-None-Match") == etag {
		writer.WriteHeader(http.StatusNotModified)
		return
	}
	header.Set("Content-Type", file.contentType)
	_, _ = writer.Write(file.body)
}
