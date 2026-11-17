package ocirelease

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/appregistry"
	"github.com/TerraScale/ts-orchestrator/internal/fleet"
	"github.com/TerraScale/ts-orchestrator/internal/releaseattest"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

const (
	releaseConfig = "application/vnd.terrascale.orchestrator.release.v1+json"
	channelConfig = "application/vnd.terrascale.orchestrator.channel.v1+json"
	binaryType    = "application/octet-stream"
	bundleType    = "application/vnd.dev.sigstore.bundle.v0.3+json"
	documentType  = "application/vnd.terrascale.orchestrator.channel.document.v1+json"
)

type Blob struct {
	Title     string
	MediaType string
	Data      []byte
}

type Image struct {
	Manifest []byte
	Blobs    map[string][]byte
}

func (i Image) Digest() string { return digestOf(i.Manifest) }

func build(configType string, blobs []Blob) Image {
	config := []byte("{}")
	image := Image{Blobs: map[string][]byte{digestOf(config): config}}
	parsed := manifest{SchemaVersion: 2, MediaType: manifestType, Config: descriptor{MediaType: configType, Digest: digestOf(config), Size: int64(len(config))}}
	slices.SortFunc(blobs, func(a, b Blob) int { return cmp.Compare(a.Title, b.Title) })
	for _, blob := range blobs {
		digest := digestOf(blob.Data)
		image.Blobs[digest] = blob.Data
		parsed.Layers = append(parsed.Layers, descriptor{MediaType: blob.MediaType, Digest: digest, Size: int64(len(blob.Data)), Annotations: map[string]string{titleKey: blob.Title}})
	}
	image.Manifest, _ = json.Marshal(parsed)
	return image
}

func ArtifactImage(binaries map[string][]byte, provenance []byte) Image {
	blobs := []Blob{{Title: releaseattest.BundleAsset, MediaType: bundleType, Data: provenance}}
	for arch, data := range binaries {
		blobs = append(blobs, Blob{Title: releaseattest.AssetPrefix + arch, MediaType: binaryType, Data: data})
	}
	return build(releaseConfig, blobs)
}

func ChannelImage(signed releaseattest.SignedChannel) Image {
	return build(channelConfig, []Blob{{Title: releaseattest.ChannelDocument, MediaType: documentType, Data: signed.Document},
		{Title: releaseattest.ChannelBundle, MediaType: bundleType, Data: signed.Bundle}})
}

type Target struct {
	Repository name.Repository
	Options    []remote.Option
	Registry   Registry
}

func OpenTarget(ctx context.Context, repository string, auth authn.Authenticator, base http.RoundTripper) (Target, error) {
	repo, err := name.NewRepository(repository)
	if err != nil {
		return Target{}, err
	}
	pull, err := transport.NewWithContext(ctx, repo.Registry, auth, base, []string{repo.Scope(transport.PullScope)})
	if err != nil {
		return Target{}, fmt.Errorf("%s: %w", repository, err)
	}
	return Target{Repository: repo, Options: []remote.Option{remote.WithContext(ctx), remote.WithAuth(auth), remote.WithTransport(base)},
		Registry: Registry{Base: "https://" + repo.RegistryStr(), Repository: repo.RepositoryStr(), Client: &http.Client{Transport: pull, Timeout: requestWait}}}, nil
}

func Destinations(ctx context.Context) ([]*appregistry.Client, error) {
	document := fleet.Embedded()
	labels := []string{}
	for _, region := range document.Regions {
		labels = append(labels, region.Label)
	}
	labels = append(labels, document.Staging.Label)
	destinations := []*appregistry.Client{}
	for _, label := range labels {
		client, err := appregistry.Regional(ctx, label)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		if _, err := client.Repository(Package); err != nil {
			return nil, fmt.Errorf("%s: %w", label, err)
		}
		destinations = append(destinations, client)
	}
	return destinations, nil
}

type rawManifest []byte

func (m rawManifest) RawManifest() ([]byte, error)        { return m, nil }
func (m rawManifest) MediaType() (types.MediaType, error) { return types.OCIManifestSchema1, nil }

func (t Target) Push(tag string, image Image) error {
	for digest, data := range image.Blobs {
		if err := remote.WriteLayer(t.Repository, static.NewLayer(data, binaryType), t.Options...); err != nil {
			return fmt.Errorf("push blob %s: %w", digest, err)
		}
	}
	if err := remote.Put(t.Repository.Tag(tag), rawManifest(image.Manifest), t.Options...); err != nil {
		return fmt.Errorf("push %s: %w", tag, err)
	}
	return nil
}

func Publish(ctx context.Context, target Target, attest releaseattest.Verifier, artifact Image, signed releaseattest.SignedChannel, output io.Writer) error {
	channel, err := attest.Channel(signed)
	if err != nil {
		return err
	}
	if artifact.Digest() != channel.Artifact {
		return fmt.Errorf("channel seq %d names artifact %s, the release is %s", channel.Seq, channel.Artifact, artifact.Digest())
	}
	if err := target.Push(channel.Tag(), artifact); err != nil {
		return err
	}
	if _, digest, err := target.Registry.Manifest(ctx, channel.Tag()); err != nil || digest != channel.Artifact {
		return fmt.Errorf("artifact %s reads back as %s: %v", channel.Tag(), digest, err)
	}
	current, _, err := Read(ctx, target.Registry, Stable)
	var missing *releaseattest.NotFoundError
	switch {
	case errors.As(err, &missing):
	case err != nil:
		return fmt.Errorf("current channel: %w", err)
	default:
		published, err := attest.Channel(current)
		if err != nil {
			fmt.Fprintf(output, "%s: current channel refused, replacing it: %v\n", target.Repository, err)
			break
		}
		if published.Seq > channel.Seq || published.Seq == channel.Seq && published.Tag() == channel.Tag() {
			fmt.Fprintf(output, "%s: channel already at seq %d (%s); left unchanged\n", target.Repository, published.Seq, published.Tag())
			_, err := Resolve(ctx, target.Registry, attest, current)
			return err
		}
		if published.Seq == channel.Seq {
			return fmt.Errorf("channel seq %d already names %s, not %s", channel.Seq, published.Tag(), channel.Tag())
		}
	}
	image := ChannelImage(signed)
	if err := target.Push(Stable, image); err != nil {
		return err
	}
	readBack, digest, err := Read(ctx, target.Registry, Stable)
	if err != nil {
		return fmt.Errorf("channel reads back: %w", err)
	}
	if digest != image.Digest() {
		return fmt.Errorf("channel reads back as %s, pushed %s", digest, image.Digest())
	}
	release, err := Resolve(ctx, target.Registry, attest, readBack)
	if err != nil {
		return fmt.Errorf("channel read back does not verify: %w", err)
	}
	fmt.Fprintf(output, "%s: channel seq %d -> %s artifact %s verified\n", target.Repository, release.Seq, release.Tag(), channel.Artifact)
	return nil
}

func ReadDist(dist string) (map[string][]byte, []byte, error) {
	binaries := map[string][]byte{}
	for _, arch := range Architectures {
		data, err := os.ReadFile(filepath.Join(dist, releaseattest.AssetPrefix+arch))
		if err != nil {
			return nil, nil, err
		}
		binaries[arch] = data
	}
	provenance, err := os.ReadFile(filepath.Join(dist, releaseattest.BundleAsset))
	return binaries, provenance, err
}

func Document(artifact Image, sha, run string, seq uint64, at time.Time) ([]byte, error) {
	data, err := json.Marshal(releaseattest.Channel{Seq: seq, SHA: sha, Run: run, Artifact: artifact.Digest(), PublishedAt: at.UTC().Truncate(time.Second)})
	if err != nil {
		return nil, err
	}
	if _, err := releaseattest.ParseChannel(data); err != nil {
		return nil, err
	}
	return data, nil
}

const usage = "usage: ts-orch release channel prepare <dist> <sha> <run> <seq> <channel.json> | publish <dist> <channel dir>"

func Run(ctx context.Context, args []string, output io.Writer) error {
	switch {
	case len(args) == 6 && args[0] == "prepare":
		binaries, provenance, err := ReadDist(args[1])
		if err != nil {
			return err
		}
		seq, err := strconv.ParseUint(args[4], 10, 64)
		if err != nil {
			return fmt.Errorf("seq: %w", err)
		}
		document, err := Document(ArtifactImage(binaries, provenance), args[2], args[3], seq, time.Now())
		if err != nil {
			return err
		}
		return os.WriteFile(args[5], document, 0o644)
	case len(args) == 3 && args[0] == "publish":
		binaries, provenance, err := ReadDist(args[1])
		if err != nil {
			return err
		}
		var signed releaseattest.SignedChannel
		if signed.Document, err = os.ReadFile(filepath.Join(args[2], releaseattest.ChannelDocument)); err != nil {
			return err
		}
		if signed.Bundle, err = os.ReadFile(filepath.Join(args[2], releaseattest.ChannelBundle)); err != nil {
			return err
		}
		attest, err := releaseattest.PublicGood()
		if err != nil {
			return err
		}
		destinations, err := Destinations(ctx)
		if err != nil {
			return err
		}
		artifact := ArtifactImage(binaries, provenance)
		var failed []error
		for _, client := range destinations {
			repository, _ := client.Repository(Package)
			err := publishTo(ctx, client, attest, artifact, signed, output)
			if err != nil {
				fmt.Fprintf(output, "%s: FAILED: %v\n", repository, err)
				failed = append(failed, fmt.Errorf("%s: %w", repository, err))
			}
		}
		return errors.Join(failed...)
	}
	return errors.New(usage)
}

func publishTo(ctx context.Context, client *appregistry.Client, attest releaseattest.Verifier, artifact Image, signed releaseattest.SignedChannel, output io.Writer) error {
	repository, err := client.Repository(Package)
	if err != nil {
		return err
	}
	repo, err := name.NewRepository(repository)
	if err != nil {
		return err
	}
	auth, err := authn.DefaultKeychain.Resolve(repo.Registry)
	if err != nil {
		return err
	}
	target, err := OpenTarget(ctx, repository, auth, client.BoundTransport(nil))
	if err != nil {
		return err
	}
	return Publish(ctx, target, attest, artifact, signed, output)
}
