package ocirelease

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync"

	"github.com/TerraScale/ts-orchestrator/internal/releaseattest"
)

const bundleLimit = 4 << 20

var Architectures = []string{"amd64", "arm64"}

type descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        descriptor   `json:"config"`
	Layers        []descriptor `json:"layers"`
}

func titled(data []byte) (map[string]descriptor, error) {
	var parsed manifest
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("%w: manifest unreadable: %v", releaseattest.ErrRefused, err)
	}
	layers := map[string]descriptor{}
	for _, layer := range parsed.Layers {
		title := layer.Annotations[titleKey]
		if _, twice := layers[title]; twice || title == "" {
			return nil, fmt.Errorf("%w: manifest layer %s has a missing or repeated title %q", releaseattest.ErrRefused, layer.Digest, title)
		}
		layers[title] = layer
	}
	return layers, nil
}

func Resolve(ctx context.Context, registry Registry, attest releaseattest.Verifier, signed releaseattest.SignedChannel) (releaseattest.Release, error) {
	channel, err := attest.Channel(signed)
	if err != nil {
		return releaseattest.Release{}, err
	}
	release := releaseattest.Release{SHA: channel.SHA, RunID: channel.Run, Seq: channel.Seq, Channel: &signed}
	data, _, err := registry.Manifest(ctx, channel.Artifact)
	var missing *releaseattest.NotFoundError
	if errors.As(err, &missing) {
		return release, fmt.Errorf("channel seq %d names artifact %s, which the registry does not hold yet: %w", channel.Seq, channel.Artifact, err)
	}
	if err != nil {
		return release, err
	}
	layers, err := titled(data)
	if err != nil {
		return release, err
	}
	provenance, ok := layers[releaseattest.BundleAsset]
	if !ok {
		return release, fmt.Errorf("%w: artifact %s has no %s", releaseattest.ErrRefused, channel.Artifact, releaseattest.BundleAsset)
	}
	bundle, err := registry.Blob(ctx, provenance.Digest, bundleLimit)
	if err != nil {
		return release, err
	}
	subjects, err := attest.Subjects(bundle, channel.SHA, channel.Run)
	if err != nil {
		return release, err
	}
	release.Bundle, release.Binaries = registry.BlobURL(provenance.Digest), map[string]releaseattest.Artifact{}
	for _, arch := range Architectures {
		layer, ok := layers[releaseattest.AssetPrefix+arch]
		if !ok {
			continue
		}
		digest := strings.TrimPrefix(layer.Digest, "sha256:")
		if subjects[releaseattest.AssetPrefix+arch] != digest {
			return release, fmt.Errorf("%w: the %s layer %s differs from its attestation", releaseattest.ErrRefused, arch, layer.Digest)
		}
		release.Binaries[arch] = releaseattest.Artifact{URL: registry.BlobURL(layer.Digest), SHA256: digest}
	}
	if len(release.Binaries) == 0 {
		return release, fmt.Errorf("%w: artifact %s holds no ts-orch binary", releaseattest.ErrRefused, channel.Artifact)
	}
	return release, nil
}

func Verify(ctx context.Context, registry Registry, attest releaseattest.Verifier, release releaseattest.Release) error {
	if release.Channel == nil {
		return fmt.Errorf("%w: release %s has no signed channel document", releaseattest.ErrRefused, release.Tag())
	}
	resolved, err := Resolve(ctx, registry, attest, *release.Channel)
	if err != nil {
		return err
	}
	if resolved.SHA != release.SHA || resolved.RunID != release.RunID || resolved.Seq != release.Seq || resolved.Bundle != release.Bundle || !maps.Equal(resolved.Binaries, release.Binaries) {
		return fmt.Errorf("%w: release %s seq %d differs from its signed channel document", releaseattest.ErrRefused, release.Tag(), release.Seq)
	}
	return nil
}

func Read(ctx context.Context, registry Registry, reference string) (releaseattest.SignedChannel, string, error) {
	data, digest, err := registry.Manifest(ctx, reference)
	if err != nil {
		return releaseattest.SignedChannel{}, "", err
	}
	layers, err := titled(data)
	if err != nil {
		return releaseattest.SignedChannel{}, digest, err
	}
	document, ok := layers[releaseattest.ChannelDocument]
	bundle, signed := layers[releaseattest.ChannelBundle]
	if !ok || !signed {
		return releaseattest.SignedChannel{}, digest, fmt.Errorf("%w: channel %s lacks %s or %s", releaseattest.ErrRefused, reference, releaseattest.ChannelDocument, releaseattest.ChannelBundle)
	}
	var channel releaseattest.SignedChannel
	if channel.Document, err = registry.Blob(ctx, document.Digest, manifestLimit); err != nil {
		return channel, digest, err
	}
	channel.Bundle, err = registry.Blob(ctx, bundle.Digest, bundleLimit)
	return channel, digest, err
}

type Reader struct {
	Registry func(context.Context) (Registry, error)
	Attest   releaseattest.Verifier

	mu      sync.Mutex
	digest  string
	release releaseattest.Release
	err     error
}

func (r *Reader) Newest(ctx context.Context) (releaseattest.Release, error) {
	registry, err := r.Registry(ctx)
	if err != nil {
		return releaseattest.Release{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, digest, err := registry.Manifest(ctx, Stable)
	if err != nil {
		return releaseattest.Release{}, err
	}
	if digest == r.digest {
		return r.release, r.err
	}
	signed, _, err := Read(ctx, registry, digest)
	release := releaseattest.Release{}
	if err == nil {
		release, err = Resolve(ctx, registry, r.Attest, signed)
	}
	if err != nil && errors.Is(err, releaseattest.ErrRefused) {
		err = fmt.Errorf("channel %s: %w", digest, err)
	}
	if err == nil || errors.Is(err, releaseattest.ErrRefused) {
		r.digest, r.release, r.err = digest, release, err
	}
	return release, err
}
