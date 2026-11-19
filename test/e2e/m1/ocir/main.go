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
	"errors"
	"fmt"
	remoteTransport "github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/apppull"
	"github.com/TerraScale/ts-orchestrator/internal/appregistry"
	"github.com/TerraScale/ts-orchestrator/internal/imagetrust"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/test/e2e/m1/sigstore"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/moby/swarmkit/v2/api"
	godigest "github.com/opencontainers/go-digest"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/sigstore/sigstore-go/pkg/root"
)

const host = "sa-saopaulo-1.ocir.io"
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
	raw, err := attachment.RawManifest()
	must(err)
	var manifest v1.Manifest
	must(json.Unmarshal(raw, &manifest))
	configHash, _, err := v1.SHA256(strings.NewReader("{}"))
	must(err)
	manifest.Config = v1.Descriptor{MediaType: types.MediaType("application/vnd.oci.empty.v1+json"), Digest: configHash, Size: 2, Data: []byte("{}")}
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
	tag, err := name.NewTag(host + "/" + repository + ":sha256-" + subject.Digest.Hex)
	must(err)
	index := v1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex, Manifests: []v1.Descriptor{}}
	existing, err := remote.Get(tag, remote.WithContext(ctx), remote.WithTransport(t), remote.WithUserAgent("ocir-journey-publisher"))
	if err == nil {
		must(json.Unmarshal(existing.Manifest, &index))
	} else {
		var status *remoteTransport.Error
		require(errors.As(err, &status) && status.StatusCode == http.StatusNotFound, "fallback index read failed")
	}
	index.Manifests = append(index.Manifests, v1.Descriptor{MediaType: types.OCIManifestSchema1, Digest: hash, Size: int64(len(raw)), ArtifactType: string(artifactType)})
	encoded, err := json.Marshal(index)
	must(err)
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, "https://"+host+"/v2/"+repository+"/manifests/"+tag.TagStr(), bytes.NewReader(encoded))
	must(err)
	request.Header.Set("Content-Type", string(types.OCIImageIndex))
	request.Header.Set("User-Agent", "ocir-journey-publisher")
	response, err := (&http.Client{Transport: t}).Do(request)
	must(err)
	must(response.Body.Close())
	require(response.StatusCode == http.StatusCreated, "fallback publication failed")

}

type artifact struct {
	v1.Image
	manifest []byte
}

func (a *artifact) RawConfigFile() ([]byte, error) { return []byte("{}"), nil }
func (a *artifact) ConfigName() (v1.Hash, error) {
	hash, _, err := v1.SHA256(strings.NewReader("{}"))
	return hash, err
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
	backend := registry.New(registry.Logger(log.New(io.Discard, "", 0)), registry.WithReferrersSupport(false))
	fallback := true
	redirectPath, redirectOrigin := "", ""
	requests := map[string]int{}
	signedHeaders := regexp.MustCompile(`headers="([^"]+)"`)
	signature := regexp.MustCompile(`signature="([^"]+)"`)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/20180419/docker/token" {
			scope := r.URL.Query().Get("scope")
			allowed := slices.ContainsFunc(apppull.Targets, func(target apppull.Target) bool {
				return scope == "repository:journey/terrascale/"+target.Package+":pull"
			})
			require(r.Method == http.MethodGet && r.URL.Query().Get("service") == host && allowed, "token request escaped pull scope")
			authorization := r.Header.Get("Authorization")
			headers := signedHeaders.FindStringSubmatch(authorization)
			sig := signature.FindStringSubmatch(authorization)
			if len(headers) != 2 || len(sig) != 2 || !strings.Contains(" "+headers[1]+" ", " date ") || r.Header.Get("Date") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if _, err := http.ParseTime(r.Header.Get("Date")); err != nil {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
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
			requests[scope]++
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "journey-regional-token", "access_token": "journey-regional-token", "scope": "", "expires_in": 3600})
			return
		}
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			if r.URL.Path != "/v2/" && r.Header.Get("Authorization") != "Bearer journey-regional-token" && !strings.Contains(r.Header.Get("User-Agent"), "ocir-journey-publisher") {
				w.Header().Set("WWW-Authenticate", "Bearer realm=\"https://"+host+"/20180419/docker/token\",service=\""+host+"\"")
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		if redirectPath != "" && r.URL.Path == redirectPath {
			http.Redirect(w, r, redirectOrigin+r.URL.Path, http.StatusTemporaryRedirect)
			return
		}
		if strings.Contains(r.URL.Path, "/referrers/") {
			if fallback {
				http.NotFound(w, r)
				return
			}
			r = r.Clone(r.Context())
			r.URL.Path = strings.Replace(r.URL.Path, "/referrers/sha256:", "/manifests/sha256-", 1)
		}
		if strings.Contains(r.URL.Path, "/ts-auth/manifests/") {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"errors": []map[string]any{{"code": "MANIFEST_UNKNOWN", "message": opaqueCredential, "detail": opaqueSignature}}})
			return
		}
		if strings.Contains(r.URL.Path, "/terrascale-dashboard/manifests/") {
			http.Error(w, opaqueCredential+" "+opaqueSignature, http.StatusBadRequest)
			return
		}
		backend.ServeHTTP(w, r)
	}))
	defer server.Close()
	endpoint, err := url.Parse(server.URL)
	must(err)
	t := transport{endpoint, server.Client().Transport}
	missingDate, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/20180419/docker/token?"+url.Values{"service": {host}, "scope": {"repository:" + repository + ":pull"}}.Encode(), nil)
	must(err)
	must(signer.Sign(missingDate))
	response, err := (&http.Client{Transport: t}).Do(missingDate)
	must(err)
	must(response.Body.Close())
	require(response.StatusCode == http.StatusUnauthorized, "token endpoint accepted an unsigned Date")
	fmt.Println("ok: token endpoint refuses missing signed Date")
	client := &appregistry.Client{Host: host, Namespace: "journey", Prefix: "terrascale", Sign: signer.Sign, Transport: t}
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
	verifyRefusalLogs(ctx, source, "terrabase@"+digest.String())
	unsigned := swarmruntime.Deployment{Repository: "TerraScale/terrascale", RunID: "2", RunAttempt: 1, Revision: revision, Image: "terrabase@" + digest.String(), Workflow: apppull.Targets[0].Workflow}
	unsignedResolver, err := swarmruntime.AppImageResolver(client, unsigned, imagetrust.Verifier{Root: trusted, Transport: t})
	must(err)
	_, _, err = unsignedResolver.Resolve(ctx, unsigned.Image)
	require(err != nil, "executor accepted unsigned image")
	fmt.Println("ok: unsigned image refused by discovery and executor")
	buildBundle := authority.Bundle(identity, revision, "1", subjects)
	attach(ctx, subject, buildBundle, t)
	identity.Trigger = "workflow_dispatch"
	attach(ctx, subject, authority.Selection(identity, revision, "2", "terrabase", map[string][]byte{"app-canary-manifest.json": raw}), t)
	selected, err := source.Pull(ctx, apppull.Targets[0])
	must(err)
	require(selected.Image == "terrabase@"+digest.String(), "fleet image gained a region or changed digest")
	deployment := swarmruntime.Deployment{Repository: selected.Claims.Repository, RunID: selected.Claims.RunID, RunAttempt: 1, Revision: revision, Image: selected.Image, Workflow: selected.Claims.JobWorkflowRef}
	resolver, err := swarmruntime.AppImageResolver(client, deployment, imagetrust.Verifier{Root: trusted, Transport: t})
	must(err)
	resolved, descriptor, err := resolver.Resolve(ctx, selected.Image)
	must(err)
	require(resolved == selected.Image && descriptor.Digest.String() == digest.String(), "executor changed the fleet digest reference")
	regional, err := client.Image(selected.Image)
	must(err)
	observation := releasepush.Observation{Images: map[string]string{"terrabase": selected.Image}, Running: map[string]string{}}
	for _, running := range []string{selected.Image, "ghcr.io/terrascale/" + selected.Image, regional} {
		observation.Running["terrabase"] = running
		must(observation.CheckImages())
	}
	for _, desired := range []string{selected.Image, "ghcr.io/terrascale/" + selected.Image, regional} {
		observation.Images["terrabase"] = desired
		must(observation.CheckImages())
	}
	for _, running := range []string{"", "terrabase:release", "terrabase@sha256:bad", "terrabase@sha256:" + strings.Repeat("f", 64)} {
		observation.Running["terrabase"] = running
		require(observation.CheckImages() != nil, "mesh gate accepted a missing, mutable, malformed or different digest")
	}
	fmt.Println("ok: mesh gate accepts reference aliases and refuses missing, mutable, malformed and different digests")
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
	fmt.Println("ok: signed Date, regional executor layer pull and offline fallback-tag provenance")
	executor, err := swarmruntime.NewExecutor(os.Args[1], os.Args[2])
	must(err)
	must(executor.SetRegistryResolver(func(context.Context, *api.Task, *api.Node) (remotes.Resolver, error) { return resolver, nil }))
	must(executor.PrePull(ctx, selected.Image, nil))
	runtimeClient, err := containerd.New(os.Args[1], containerd.WithDefaultNamespace("terrascale"))
	must(err)
	pulled, err := runtimeClient.GetImage(ctx, selected.Image)
	must(err)
	unpacked, err := pulled.IsUnpacked(ctx, "overlayfs")
	must(err)
	require(pulled.Target().Digest.String() == digest.String() && unpacked, "containerd stored another digest or left the selected image packed")
	must(executor.PrePull(ctx, selected.Image, nil))
	must(runtimeClient.Close())
	must(executor.Close())
	fmt.Println("ok: containerd pulls and unpacks the selected regional image under its fleet name")
	configDigest, err := image.ConfigName()
	must(err)
	bundleDigest, _, err := v1.SHA256(bytes.NewReader(buildBundle))
	must(err)
	for _, origin := range []string{"https://another-region.ocir.io", "http://" + host} {
		redirectOrigin = origin
		redirectPath = "/v2/" + repository + "/blobs/" + configDigest.String()
		_, err = source.Pull(ctx, apppull.Targets[0])
		require(err != nil && errors.Is(err, appregistry.ErrOutsideRegionalOCIR), "discovery followed a config redirect outside regional OCIR")
		redirectPath = "/v2/" + repository + "/blobs/" + bundleDigest.String()
		_, err = source.Pull(ctx, apppull.Targets[0])
		require(err != nil && errors.Is(err, appregistry.ErrOutsideRegionalOCIR), "discovery followed a bundle redirect outside regional OCIR")
		_, _, err = resolver.Resolve(ctx, selected.Image)
		require(err != nil && errors.Is(err, appregistry.ErrOutsideRegionalOCIR), "executor followed a bundle redirect outside regional OCIR")
		redirectPath = "/v2/" + repository + "/blobs/" + manifest.Layers[0].Digest.String()
		blob, err = fetcher.Fetch(ctx, imagespec.Descriptor{MediaType: string(manifest.Layers[0].MediaType), Digest: godigest.Digest(manifest.Layers[0].Digest.String()), Size: manifest.Layers[0].Size})
		if err == nil {
			_, err = io.Copy(io.Discard, blob)
			err = errors.Join(err, blob.Close())
		}
		require(err != nil, "executor followed a layer redirect outside regional OCIR")
	}
	redirectPath = ""
	fmt.Println("ok: discovery, offline verification and executor refuse cross-host and HTTP redirects")
	fallback = false
	selected, err = source.Pull(ctx, apppull.Targets[0])
	must(err)
	require(selected.Claims.RunID == "2", "referrers API changed verified identity")
	fmt.Println("ok: offline OCI referrers API provenance also verifies")
	fallback = true
	changed, err := mutate.ConfigFile(image, &v1.ConfigFile{OS: "linux", Architecture: runtime.GOARCH, Config: v1.Config{Labels: config.Config.Labels, Cmd: []string{"tampered"}}})
	must(err)
	must(remote.Write(tag, changed, remote.WithContext(ctx), remote.WithTransport(t), remote.WithUserAgent("ocir-journey-publisher")))
	changedRaw, err := changed.RawManifest()
	must(err)
	changedDigest, err := changed.Digest()
	must(err)
	changedSubject := &v1.Descriptor{MediaType: types.OCIManifestSchema1, Digest: changedDigest, Size: int64(len(changedRaw))}
	attach(ctx, changedSubject, authority.Bundle(identity, revision, "1", subjects), t)
	attach(ctx, changedSubject, authority.Selection(identity, revision, "2", "terrabase", map[string][]byte{"app-canary-manifest.json": raw}), t)
	_, err = source.Pull(ctx, apppull.Targets[0])
	require(err != nil, "tampered image accepted another digest provenance")
	deployment.Image = "terrabase@" + changedDigest.String()
	resolver, err = swarmruntime.AppImageResolver(client, deployment, imagetrust.Verifier{Root: trusted, Transport: t})
	must(err)
	_, _, err = resolver.Resolve(ctx, deployment.Image)
	require(err != nil, "executor accepted tampered image")
	fmt.Println("ok: tampered image with copied bundles refused by discovery and executor")
	for _, target := range apppull.Targets {
		require(requests["repository:journey/terrascale/"+target.Package+":pull"] == 1, "token was not cached across pulls")
	}
	fmt.Println("ok: instance-principal token cached in memory")
	for _, label := range []string{"gru", "sjc", "fra"} {
		configuration, err := appregistry.ConfigurationFor(label)
		must(err)
		expected := "terrascale"
		require(configuration.Namespace == "grxnmoqvrcdv" && configuration.Prefix == expected, "embedded registry environment is incorrect")
		registry, err := appregistry.Regional(ctx, label)
		must(err)
		physical, err := registry.Image("terrabase@" + digest.String())
		must(err)
		require(strings.Contains(physical, "/grxnmoqvrcdv/"+expected+"/terrabase@"), "host expanded the wrong environment repository")
	}
	fmt.Println("ok: production regions expand the same package digest into regional repositories")
}

func privatePEM(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}
