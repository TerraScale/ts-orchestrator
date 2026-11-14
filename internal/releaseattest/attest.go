package releaseattest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/imagetrust"
	bundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	Repository    = "TerraScale/ts-orchestrator"
	Workflow      = Repository + "/.github/workflows/ci.yml@" + MainRef
	MainRef       = "refs/heads/main"
	BundleAsset   = "provenance.sigstore.json"
	AssetPrefix   = "terrascale-orchestrator-linux-"
	actionsIssuer = "https://token.actions.githubusercontent.com"
	repositoryURL = "https://github.com/" + Repository
	downloadURL   = repositoryURL + "/releases/download/"
	provenanceV1  = "https://slsa.dev/provenance/v1"
	bundleLimit   = 4 << 20
)

var (
	sha40 = regexp.MustCompile(`^[0-9a-f]{40}$`)
	runID = regexp.MustCompile(`^[0-9]{1,20}$`)
	hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

var ErrRefused = errors.New("release refused")

type Artifact struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

type Release struct {
	SHA      string              `json:"sha"`
	RunID    string              `json:"run_id"`
	Binaries map[string]Artifact `json:"binaries"`
	Bundle   string              `json:"bundle"`
}

func Tag(sha, run string) string { return "ci-" + sha + "-run-" + run }

func AssetURL(sha, run, name string) string { return downloadURL + Tag(sha, run) + "/" + name }

func (r Release) Tag() string { return Tag(r.SHA, r.RunID) }

func (r Release) Validate() error {
	if !sha40.MatchString(r.SHA) || !runID.MatchString(r.RunID) {
		return fmt.Errorf("%w: sha must be 40 lowercase hex and run_id a number", ErrRefused)
	}
	if r.Bundle != AssetURL(r.SHA, r.RunID, BundleAsset) {
		return fmt.Errorf("%w: bundle must be %s", ErrRefused, AssetURL(r.SHA, r.RunID, BundleAsset))
	}
	if len(r.Binaries) == 0 {
		return fmt.Errorf("%w: no binaries", ErrRefused)
	}
	for arch, binary := range r.Binaries {
		if want := AssetURL(r.SHA, r.RunID, AssetPrefix+arch); binary.URL != want {
			return fmt.Errorf("%w: %s url must be %s", ErrRefused, arch, want)
		}
		if binary.SHA256 != "" && !hex64.MatchString(binary.SHA256) {
			return fmt.Errorf("%w: %s sha256 must be 64 lowercase hex", ErrRefused, arch)
		}
	}
	return nil
}

type Verifier struct {
	Root root.TrustedMaterial
}

func PublicGood() (Verifier, error) {
	trusted, err := imagetrust.PublicGoodRoot()
	if err != nil {
		return Verifier{}, err
	}
	return Verifier{Root: trusted}, nil
}

func (v Verifier) Subjects(data []byte, sha, run string) (map[string]string, error) {
	if v.Root == nil {
		return nil, errors.New("no sigstore trusted root")
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(data); err != nil {
		return nil, fmt.Errorf("%w: provenance bundle unreadable: %v", ErrRefused, err)
	}
	identity, err := verify.NewShortCertificateIdentity(actionsIssuer, "", "https://github.com/"+Workflow, "")
	if err != nil {
		return nil, err
	}
	verifier, err := verify.NewVerifier(v.Root, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	if err != nil {
		return nil, err
	}
	result, err := verifier.Verify(&b, verify.NewPolicy(verify.WithoutArtifactUnsafe(), verify.WithCertificateIdentity(identity)))
	if err != nil {
		return nil, fmt.Errorf("%w: provenance not signed by https://github.com/%s: %v", ErrRefused, Workflow, err)
	}
	if result.Statement == nil || result.Statement.GetPredicateType() != provenanceV1 {
		return nil, fmt.Errorf("%w: attestation is not SLSA provenance v1", ErrRefused)
	}
	if result.Signature == nil || result.Signature.Certificate == nil {
		return nil, fmt.Errorf("%w: attestation has no signing certificate", ErrRefused)
	}
	certificate := result.Signature.Certificate
	switch {
	case certificate.SourceRepositoryURI != repositoryURL:
		return nil, fmt.Errorf("%w: attestation is for repository %q", ErrRefused, certificate.SourceRepositoryURI)
	case certificate.SourceRepositoryRef != MainRef:
		return nil, fmt.Errorf("%w: attestation is for ref %q, not %s", ErrRefused, certificate.SourceRepositoryRef, MainRef)
	case certificate.SourceRepositoryDigest != sha:
		return nil, fmt.Errorf("%w: attestation is for commit %q, not %s", ErrRefused, certificate.SourceRepositoryDigest, sha)
	case certificate.BuildSignerURI != "https://github.com/"+Workflow:
		return nil, fmt.Errorf("%w: attestation was signed by workflow %q", ErrRefused, certificate.BuildSignerURI)
	case certificate.BuildTrigger != "push":
		return nil, fmt.Errorf("%w: attestation was built by a %q event, not a push", ErrRefused, certificate.BuildTrigger)
	case !strings.HasPrefix(certificate.RunInvocationURI, repositoryURL+"/actions/runs/"+run+"/attempts/"):
		return nil, fmt.Errorf("%w: attestation was made by run %q, not run %s", ErrRefused, certificate.RunInvocationURI, run)
	}
	subjects := map[string]string{}
	for _, subject := range result.Statement.GetSubject() {
		digest := subject.GetDigest()["sha256"]
		if strings.HasPrefix(subject.GetName(), AssetPrefix) && hex64.MatchString(digest) {
			subjects[subject.GetName()] = digest
		}
	}
	if len(subjects) == 0 {
		return nil, fmt.Errorf("%w: attestation names no ts-orch binary", ErrRefused)
	}
	return subjects, nil
}

func (v Verifier) Attested(ctx context.Context, client *http.Client, release Release) (Release, error) {
	if err := release.Validate(); err != nil {
		return Release{}, err
	}
	data, err := Download(ctx, client, release.Bundle, bundleLimit)
	if err != nil {
		return Release{}, err
	}
	subjects, err := v.Subjects(data, release.SHA, release.RunID)
	if err != nil {
		return Release{}, err
	}
	attested := release
	attested.Binaries = map[string]Artifact{}
	for arch, binary := range release.Binaries {
		digest, ok := subjects[AssetPrefix+arch]
		if !ok {
			return Release{}, fmt.Errorf("%w: attestation does not name %s%s", ErrRefused, AssetPrefix, arch)
		}
		if binary.SHA256 != "" && binary.SHA256 != digest {
			return Release{}, fmt.Errorf("%w: %s digest differs from its attestation", ErrRefused, arch)
		}
		binary.SHA256 = digest
		attested.Binaries[arch] = binary
	}
	return attested, nil
}

type NotFoundError struct{ URL string }

func (e *NotFoundError) Error() string { return "not found: " + e.URL }

func Download(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return nil, &NotFoundError{url}
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: %s", url, response.Status)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err == nil && int64(len(data)) > limit {
		err = fmt.Errorf("download %s: larger than %d bytes", url, limit)
	}
	return data, err
}
