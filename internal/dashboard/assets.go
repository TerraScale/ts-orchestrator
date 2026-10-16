package dashboard

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
)

// The vendored client files are pinned copies served from the binary; no page
// loads anything from a CDN. assets/VENDOR.md records each file's upstream
// release, URL and sha256:
//
//   - dashboard.css includes the pinned Pico CSS v2.1.1 base (MIT).
//   - datastar.js: Datastar v1.0.4 (MIT).
//   - echarts.min.js: Apache ECharts 5.6.0 (Apache-2.0).
//   - world.json: the world GeoJSON shipped with Apache ECharts 4.9.0.
//   - app.js and dashboard.css: this slice's own elements and styles.
//
//go:embed assets/*.css assets/*.js assets/*.json
var assetFiles embed.FS

// asset is one embedded file addressed by its content hash, so a response can
// be cached forever and a new binary changes every URL whose content changed.
// Large text assets are also served gzip-compressed.
type asset struct {
	body        []byte
	gzipped     func() []byte
	hash        string
	contentType string
}

// gzipThreshold is the size above which an asset is served compressed to
// clients that accept gzip; ECharts and the world map shrink about 3x.
const gzipThreshold = 8 << 10

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
		switch {
		case strings.HasSuffix(entry.Name(), ".js"):
			contentType = "text/javascript; charset=utf-8"
		case strings.HasSuffix(entry.Name(), ".json"):
			contentType = "application/json"
		}
		file := asset{body: body, hash: hex.EncodeToString(sum[:6]), contentType: contentType}
		if len(body) >= gzipThreshold {
			// Compressed on first request, not at startup: every CLI
			// invocation of the binary initializes this package.
			file.gzipped = sync.OnceValue(func() []byte {
				var compressed bytes.Buffer
				writer, _ := gzip.NewWriterLevel(&compressed, gzip.BestCompression)
				_, _ = writer.Write(body)
				_ = writer.Close()
				return compressed.Bytes()
			})
		}
		loaded[entry.Name()] = file
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
	header.Set("Vary", "Accept-Encoding")
	if request.Header.Get("If-None-Match") == etag {
		writer.WriteHeader(http.StatusNotModified)
		return
	}
	header.Set("Content-Type", file.contentType)
	if file.gzipped != nil && acceptsGzip(request.Header.Get("Accept-Encoding")) {
		header.Set("Content-Encoding", "gzip")
		_, _ = writer.Write(file.gzipped())
		return
	}
	_, _ = writer.Write(file.body)
}

func acceptsGzip(header string) bool {
	for part := range strings.SplitSeq(header, ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if strings.EqualFold(strings.TrimSpace(name), "gzip") {
			return qualityAbove0(params)
		}
	}
	return false
}

// qualityAbove0 reads the q parameter of an Accept-Encoding entry: q=0,
// q=0.0 or q=0.000 refuse the encoding; a missing or unreadable q accepts.
func qualityAbove0(params string) bool {
	for param := range strings.SplitSeq(params, ";") {
		key, value, _ := strings.Cut(strings.TrimSpace(param), "=")
		if !strings.EqualFold(strings.TrimSpace(key), "q") {
			continue
		}
		quality, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
		return err != nil || quality > 0
	}
	return true
}
