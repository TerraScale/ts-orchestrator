package oraclehost

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/ocirelease"
)

const (
	ocirSuffix = ".ocir.io"
	ocirToken  = "oracle-regions-ocir-pull"
)

var stablePath = regexp.MustCompile(`^/v2/(.+)/manifests/` + ocirelease.Stable + `$`)

func (f *Fleet) PublishChannel(artifact, channel ocirelease.Image) error {
	dir := filepath.Join(f.Registry, "blobs", "sha256")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, image := range []ocirelease.Image{artifact, channel} {
		blobs := map[string][]byte{image.Digest(): image.Manifest}
		for digest, data := range image.Blobs {
			blobs[digest] = data
		}
		for digest, data := range blobs {
			if err := os.WriteFile(filepath.Join(dir, strings.TrimPrefix(digest, "sha256:")), data, 0o644); err != nil {
				return err
			}
		}
	}
	f.standIn.mu.Lock()
	f.standIn.stable = channel.Digest()
	f.standIn.mu.Unlock()
	return nil
}

func (f *Fleet) ChannelRequests(host string) map[string]int {
	f.standIn.mu.Lock()
	defer f.standIn.mu.Unlock()
	served := map[string]int{}
	for key, count := range f.standIn.served {
		if strings.HasPrefix(key, host+" ") {
			served[strings.TrimPrefix(key, host+" ")] = count
		}
	}
	return served
}

func (s *standIn) ocir(w http.ResponseWriter, r *http.Request, host string) {
	if r.URL.Path == "/20180419/docker/token" {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
			serviceError(w, http.StatusUnauthorized, "NotAuthenticated", "the OCIR token exchange needs an instance-principal signature")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"token": ocirToken, "expires_in": 3600})
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+ocirToken {
		serviceError(w, http.StatusUnauthorized, "UNAUTHORIZED", "OCIR pulls need the exchanged registry token")
		return
	}
	kind := "blob"
	if strings.Contains(r.URL.Path, "/manifests/") {
		kind = "manifest"
	}
	if stablePath.MatchString(r.URL.Path) {
		s.mu.Lock()
		stable := s.stable
		s.mu.Unlock()
		if stable == "" {
			serviceError(w, http.StatusNotFound, "MANIFEST_UNKNOWN", "no release channel is published")
			return
		}
		kind = ocirelease.Stable
		r = r.Clone(r.Context())
		r.URL.Path = strings.TrimSuffix(r.URL.Path, ocirelease.Stable) + stable
	}
	s.mu.Lock()
	if s.served == nil {
		s.served = map[string]int{}
	}
	s.served[host+" "+kind]++
	s.mu.Unlock()
	s.registry(w, r)
}
