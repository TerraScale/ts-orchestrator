package oraclehost

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

const registryHost = "registry-1.docker.io"

var registryPath = regexp.MustCompile(`^/v2/(.+)/(manifests|blobs)/(sha256:[0-9a-f]{64})$`)

func FetchImage(ctx context.Context, ref, dir string) error {
	parsed, err := name.ParseReference(ref)
	if err != nil {
		return err
	}
	image, err := remote.Image(parsed, remote.WithContext(ctx))
	if err != nil {
		return err
	}
	path, err := layout.Write(dir, empty.Index)
	if err != nil {
		return err
	}
	return path.AppendImage(image)
}

func (s *standIn) registry(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v2/" {
		w.WriteHeader(http.StatusOK)
		return
	}
	match := registryPath.FindStringSubmatch(r.URL.Path)
	if match == nil || s.fleet.Registry == "" {
		serviceError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "the registry stand-in serves content by digest only")
		return
	}
	data, err := os.ReadFile(filepath.Join(s.fleet.Registry, "blobs", "sha256", strings.TrimPrefix(match[3], "sha256:")))
	if err != nil {
		serviceError(w, http.StatusNotFound, "BLOB_UNKNOWN", match[3])
		return
	}
	media := "application/octet-stream"
	if match[2] == "manifests" {
		var manifest struct {
			MediaType string `json:"mediaType"`
		}
		if json.Unmarshal(data, &manifest) != nil || manifest.MediaType == "" {
			serviceError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", match[3])
			return
		}
		media = manifest.MediaType
	}
	w.Header().Set("Content-Type", media)
	w.Header().Set("Docker-Content-Digest", match[3])
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}
