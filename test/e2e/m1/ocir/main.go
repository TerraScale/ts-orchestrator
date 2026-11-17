package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/TerraScale/ts-orchestrator/internal/imagetrust"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/apppull"
	"github.com/TerraScale/ts-orchestrator/internal/appregistry"
	"github.com/TerraScale/ts-orchestrator/test/e2e/m1/sigstore"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	godigest "github.com/opencontainers/go-digest"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/sigstore/sigstore-go/pkg/root"
)

const host = "gru.ocir.io"
const repository = "journey/terrascale/terrabase"
const revision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const artifactType = types.MediaType("application/vnd.dev.sigstore.bundle.v0.3+json")

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func require(ok bool, message string) {
	if !ok {
		panic(message)
	}
}

type transport struct {
	endpoint *url.URL
	next     http.RoundTripper
}

func (t transport) RoundTrip(request *http.Request) (*http.Response, error) {
	require(request.URL.Host == host && request.URL.Scheme == "https", "offline pull escaped regional OCIR: "+request.URL.Scheme+"://"+request.URL.Host+request.URL.Path)
	original := request
	request = request.Clone(request.Context())
	endpoint := *request.URL
	endpoint.Scheme, endpoint.Host = t.endpoint.Scheme, t.endpoint.Host
	request.URL = &endpoint
	request.Host = host
	request.Header.Set("X-Forwarded-Proto", "https")
	response, err := t.next.RoundTrip(request)
	if response != nil {
		response.Request = original
	}
	return response, err
}

func attach(ctx context.Context, subject *v1.Descriptor, data []byte, t transport) {
	layer := static.NewLayer(data, artifactType)
	attachment, err := mutate.Append(empty.Image, mutate.Addendum{Layer: layer})
	must(err)
	attachment = mutate.MediaType(attachment, types.OCIManifestSchema1)
	attachment = mutate.ConfigMediaType(attachment, artifactType)
	raw, err := attachment.RawManifest()
	must(err)
	var manifest v1.Manifest
	must(json.Unmarshal(raw, &manifest))
	manifest.Subject = subject
	manifest.ArtifactType = string(artifactType)
	raw, err = json.Marshal(manifest)
	must(err)
	attachment = &artifact{Image: attachment, manifest: raw}
	hash, err := attachment.Digest()
	must(err)
	ref, err := name.NewDigest(host + "/" + repository + "@" + hash.String())
	must(err)
	must(remote.Write(ref, attachment, remote.WithContext(ctx), remote.WithTransport(t), remote.WithUserAgent("ocir-journey-publisher")))
}

type artifact struct {
	v1.Image
	manifest []byte
}

func (a *artifact) RawManifest() ([]byte, error) { return a.manifest, nil }
func (a *artifact) Digest() (v1.Hash, error) {
	hash, _, err := v1.SHA256(strings.NewReader(string(a.manifest)))
	return hash, err
}
func (a *artifact) Size() (int64, error) { return int64(len(a.manifest)), nil }

func main() {
	ctx := context.Background()
	authority := sigstore.New()
	trusted, err := root.NewTrustedRootFromJSON(authority.TrustedRoot())
	must(err)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	provider := common.NewRawConfigurationProvider("tenancy", "instance", "region", "fingerprint", string(privatePEM(key)), nil)
	signer := common.DefaultRequestSigner(provider)
	backend := registry.New(registry.Logger(log.New(io.Discard, "", 0)), registry.WithReferrersSupport(true))
	fallback := false
	requests := 0
	signedHeaders := regexp.MustCompile(`headers="([^"]+)"`)
	signature := regexp.MustCompile(`signature="([^"]+)"`)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/20180419/docker/token" {
			require(r.Method == http.MethodGet && r.URL.Query().Get("service") == host && r.URL.Query().Get("scope") == "repository:"+repository+":pull", "token request escaped pull scope")
			authorization := r.Header.Get("Authorization")
			headers := signedHeaders.FindStringSubmatch(authorization)
			sig := signature.FindStringSubmatch(authorization)
			require(len(headers) == 2 && len(sig) == 2, "token request lacks OCI signature")
			lines := []string{}
			for _, header := range strings.Fields(headers[1]) {
				value := r.Header.Get(header)
				switch header {
				case "(request-target)":
					value = "get " + r.URL.RequestURI()
				case "host":
					value = host
				}
				lines = append(lines, header+": "+value)
			}
			hash := sha256.Sum256([]byte(strings.Join(lines, "\n")))
			value, err := base64.StdEncoding.DecodeString(sig[1])
			must(err)
			must(rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, hash[:], value))
			requests++
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "journey-regional-token", "expires_in": 300, "issued_at": time.Now().UTC()})
			return
		}
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			if r.URL.Path != "/v2/" && r.Header.Get("Authorization") != "Bearer journey-regional-token" && !strings.Contains(r.Header.Get("User-Agent"), "ocir-journey-publisher") {
				w.Header().Set("WWW-Authenticate", `Bearer realm="https://gru.ocir.io/20180419/docker/token",service="gru.ocir.io"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		if fallback && strings.Contains(r.URL.Path, "/referrers/") {
			http.NotFound(w, r)
			return
		}
		backend.ServeHTTP(w, r)
	}))
	defer server.Close()
	endpoint, err := url.Parse(server.URL)
	must(err)
	t := transport{endpoint, server.Client().Transport}
	client := &appregistry.Client{Host: host, Namespace: "journey", Sign: signer.Sign, Transport: t}
	source := apppull.Source{Registry: func(context.Context) (*appregistry.Client, error) { return client, nil }, Root: trusted, Transport: t}
	config := &v1.ConfigFile{OS: "linux", Architecture: runtime.GOARCH, Config: v1.Config{Labels: map[string]string{"org.opencontainers.image.revision": revision}}}
	var archive bytes.Buffer
	tarball := tar.NewWriter(&archive)
	payload := []byte("regional app image content")
	must(tarball.WriteHeader(&tar.Header{Name: "marker", Mode: 0644, Size: int64(len(payload))}))
	_, err = tarball.Write(payload)
	must(err)
	must(tarball.Close())
	layered, err := mutate.Append(empty.Image, mutate.Addendum{Layer: static.NewLayer(archive.Bytes(), types.OCIUncompressedLayer)})
	must(err)
	layerConfig, err := layered.ConfigFile()
	must(err)
	config.RootFS = layerConfig.RootFS
	image, err := mutate.ConfigFile(layered, config)
	must(err)
	image = mutate.MediaType(image, types.OCIManifestSchema1)
	tag, err := name.NewTag(host + "/" + repository + ":release")
	must(err)
	must(remote.Write(tag, image, remote.WithContext(ctx), remote.WithTransport(t), remote.WithUserAgent("ocir-journey-publisher")))
	digest, err := image.Digest()
	must(err)
	raw, err := image.RawManifest()
	must(err)
	subject := &v1.Descriptor{MediaType: types.OCIManifestSchema1, Digest: digest, Size: int64(len(raw))}
	subjects := map[string][]byte{host + "/" + repository: raw}
	identity := sigstore.Identity{Workflow: apppull.Targets[0].Workflow, Ref: "refs/heads/main", Trigger: "push"}
	_, err = source.Pull(ctx, apppull.Targets[0])
	require(err != nil, "unsigned image accepted")
	unsigned := swarmruntime.Deployment{Repository: "TerraScale/terrascale", RunID: "2", RunAttempt: 1, Revision: revision, Image: repository + "@" + digest.String(), Workflow: apppull.Targets[0].Workflow}
	unsignedResolver, err := swarmruntime.AppImageResolver(client, unsigned, imagetrust.Verifier{Root: trusted, Transport: t})
	must(err)
	_, _, err = unsignedResolver.Resolve(ctx, unsigned.Image)
	require(err != nil, "executor accepted unsigned image")
	fmt.Println("ok: unsigned image refused by discovery and executor")
	attach(ctx, subject, authority.Bundle(identity, revision, "1", subjects), t)
	identity.Trigger = "workflow_dispatch"
	attach(ctx, subject, authority.Selection(identity, revision, "2", "terrabase", subjects), t)
	selected, err := source.Pull(ctx, apppull.Targets[0])
	must(err)
	require(selected.Image == repository+"@"+digest.String(), "fleet image gained a region or changed digest")
	deployment := swarmruntime.Deployment{Repository: selected.Claims.Repository, RunID: selected.Claims.RunID, RunAttempt: 1, Revision: revision, Image: selected.Image, Workflow: selected.Claims.JobWorkflowRef}
	resolver, err := swarmruntime.AppImageResolver(client, deployment, imagetrust.Verifier{Root: trusted, Transport: t})
	must(err)
	resolved, descriptor, err := resolver.Resolve(ctx, selected.Image)
	must(err)
	require(resolved == selected.Image && descriptor.Digest.String() == digest.String(), "executor changed the fleet digest reference")
	fetcher, err := resolver.Fetcher(ctx, selected.Image)
	must(err)
	manifest, err := image.Manifest()
	must(err)
	require(len(manifest.Layers) == 1, "image omitted the app layer")
	blob, err := fetcher.Fetch(ctx, imagespec.Descriptor{MediaType: string(manifest.Layers[0].MediaType), Digest: godigest.Digest(manifest.Layers[0].Digest.String()), Size: manifest.Layers[0].Size})
	must(err)
	content, err := io.ReadAll(blob)
	must(err)
	must(blob.Close())
	require(bytes.Equal(content, archive.Bytes()), "executor pulled different app layer bytes")
	fmt.Println("ok: signed token, regional layer pull and offline referrers API provenance")
	keychain, err := client.Keychain(ctx, repository)
	must(err)
	pinned, err := name.NewDigest(host + "/" + repository + "@" + digest.String())
	must(err)
	referrers, err := remote.Referrers(pinned, remote.WithContext(ctx), remote.WithTransport(t), remote.WithAuthFromKeychain(keychain))
	must(err)
	fallbackRaw, err := referrers.RawManifest()
	must(err)
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, "https://"+host+"/v2/"+repository+"/manifests/sha256-"+digest.Hex, strings.NewReader(string(fallbackRaw)))
	must(err)
	request.Header.Set("Content-Type", string(types.OCIImageIndex))
	request.Header.Set("User-Agent", "ocir-journey-publisher")
	response, err := (&http.Client{Transport: t}).Do(request)
	must(err)
	must(response.Body.Close())
	require(response.StatusCode == http.StatusCreated, "fallback publication failed")
	fallback = true
	selected, err = source.Pull(ctx, apppull.Targets[0])
	must(err)
	require(selected.Claims.RunID == "2", "fallback changed verified identity")
	fmt.Println("ok: offline OCI referrers fallback tag provenance")
	fallback = false
	changed, err := mutate.ConfigFile(image, &v1.ConfigFile{OS: "linux", Architecture: runtime.GOARCH, Config: v1.Config{Labels: config.Config.Labels, Cmd: []string{"tampered"}}})
	must(err)
	must(remote.Write(tag, changed, remote.WithContext(ctx), remote.WithTransport(t), remote.WithUserAgent("ocir-journey-publisher")))
	changedRaw, err := changed.RawManifest()
	must(err)
	changedDigest, err := changed.Digest()
	must(err)
	changedSubject := &v1.Descriptor{MediaType: types.OCIManifestSchema1, Digest: changedDigest, Size: int64(len(changedRaw))}
	attach(ctx, changedSubject, authority.Bundle(identity, revision, "1", subjects), t)
	attach(ctx, changedSubject, authority.Selection(identity, revision, "2", "terrabase", subjects), t)
	_, err = source.Pull(ctx, apppull.Targets[0])
	require(err != nil, "tampered image accepted another digest provenance")
	deployment.Image = repository + "@" + changedDigest.String()
	resolver, err = swarmruntime.AppImageResolver(client, deployment, imagetrust.Verifier{Root: trusted, Transport: t})
	must(err)
	_, _, err = resolver.Resolve(ctx, deployment.Image)
	require(err != nil, "executor accepted tampered image")
	fmt.Println("ok: tampered image with copied bundles refused by discovery and executor")
	require(requests == 1, "token was not cached across pulls")
	fmt.Println("ok: instance-principal token cached in memory")
	_, err = appregistry.Namespace()
	must(err)
	fmt.Println("ok: embedded fleet OCIR namespace is set")
}

func privatePEM(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}
