package releasegate

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"regexp"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/releaseattest"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	Workflow      = releaseattest.Repository + "/.github/workflows/staging-admission.yml@" + releaseattest.MainRef
	PredicateType = "https://terrascale.tech/attestations/admit-without-staging/v1"
	BundleAsset   = "staging-admission.sigstore.json"
	FetchWait     = time.Minute
	Lifetime      = 24 * time.Hour
)

var invocation = regexp.MustCompile(`^https://github.com/TerraScale/ts-orchestrator/actions/runs/([0-9]{1,20})/attempts/([1-9][0-9]*)$`)
var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var revisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

type Target struct {
	Binaries map[string]string `json:"binaries"`
	Tag      string            `json:"tag"`
}

type Attestation struct {
	Target
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Reason    string    `json:"reason"`
}

type Receipt struct {
	Target
	Region string    `json:"region"`
	RunID  string    `json:"run_id,omitempty"`
	At     time.Time `json:"at,omitzero"`
}

func (r Receipt) Message() string {
	if r.RunID != "" {
		return "admitted without staging by run " + r.RunID
	}
	return "admitted by staging"
}

type Refusal struct {
	Code   string
	Reason string
}

func (e *Refusal) Error() string { return "staging gate " + e.Code + ": " + e.Reason }

type Verifier struct {
	Client     *http.Client
	Attest     releaseattest.Verifier
	StagingKey *ecdsa.PublicKey
}

func ReleaseTarget(release releaseattest.Release) Target {
	target := Target{Tag: release.Tag(), Binaries: map[string]string{}}
	for arch, binary := range release.Binaries {
		target.Binaries[arch] = binary.SHA256
	}
	return target
}

func (t Target) Document() ([]byte, error) {
	data, err := json.Marshal(t)
	return append(data, '\n'), err
}

func (v Verifier) Check(ctx context.Context, region string, release releaseattest.Release, source Origin) (receipt Receipt, failure error) {
	defer func() { RecordBlock(source, region, failure) }()
	receipt = Receipt{Target: ReleaseTarget(release), Region: region, At: time.Now().UTC()}
	if region == scope.Staging.Label {
		return receipt, nil
	}
	if !Production(region) {
		return Receipt{}, errors.New("release admission: unknown region " + region)
	}
	if v.Client == nil || v.StagingKey == nil {
		return Receipt{}, errors.New("release admission verifier is incomplete")
	}
	code, reason := v.staging(ctx, receipt.Target)
	if code == "" {
		return receipt, nil
	}
	run, err := v.withoutStaging(ctx, receipt.Target)
	if err == nil {
		receipt.RunID = run
		return receipt, nil
	}
	return Receipt{}, &Refusal{Code: code, Reason: reason + "; admit-without-staging: " + err.Error()}
}

func (v Verifier) withoutStaging(ctx context.Context, target Target) (string, error) {
	fetch, cancel := context.WithTimeout(ctx, FetchWait)
	defer cancel()
	data, err := releaseattest.Download(fetch, v.Client, "https://github.com/"+releaseattest.Repository+"/releases/download/"+target.Tag+"/"+BundleAsset, 4<<20)
	if err != nil {
		return "", err
	}
	return v.VerifyAttestation(data, target, time.Now())
}

func (v Verifier) VerifyAttestation(data []byte, target Target, now time.Time) (string, error) {
	if v.Attest.Root == nil || len(target.Binaries) == 0 {
		return "", errors.New("admission has no trusted root or binary digests")
	}
	for _, digest := range target.Binaries {
		if !digestPattern.MatchString(digest) {
			return "", errors.New("admission target has an invalid binary digest")
		}
	}
	var signed bundle.Bundle
	if err := signed.UnmarshalJSON(data); err != nil {
		return "", fmt.Errorf("admission bundle: %w", err)
	}
	identity, err := verify.NewShortCertificateIdentity("https://token.actions.githubusercontent.com", "", "https://github.com/"+Workflow, "")
	if err != nil {
		return "", err
	}
	verifier, err := verify.NewVerifier(v.Attest.Root, verify.WithSignedCertificateTimestamps(1), verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	if err != nil {
		return "", err
	}
	document, err := target.Document()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(document)
	result, err := verifier.Verify(&signed, verify.NewPolicy(verify.WithArtifactDigest("sha256", digest[:]), verify.WithCertificateIdentity(identity)))
	if err != nil {
		return "", fmt.Errorf("admission signature: %w", err)
	}
	if result.Statement == nil || result.Statement.PredicateType != PredicateType || result.Statement.Predicate == nil || result.Signature == nil || result.Signature.Certificate == nil {
		return "", errors.New("not an admit-without-staging attestation")
	}
	cert := result.Signature.Certificate
	run := invocation.FindStringSubmatch(cert.RunInvocationURI)
	if cert.SourceRepositoryURI != "https://github.com/"+releaseattest.Repository || cert.SourceRepositoryRef != releaseattest.MainRef || !revisionPattern.MatchString(cert.SourceRepositoryDigest) || cert.BuildSignerURI != "https://github.com/"+Workflow || cert.BuildTrigger != "workflow_dispatch" || run == nil {
		return "", errors.New("admission requires the repository main dispatch workflow")
	}
	payload, err := json.Marshal(result.Statement.Predicate.AsMap())
	if err != nil {
		return "", err
	}
	var admission Attestation
	if err := json.Unmarshal(payload, &admission); err != nil {
		return "", err
	}
	if admission.Tag != target.Tag || !maps.Equal(admission.Binaries, target.Binaries) || admission.Reason == "" {
		return "", errors.New("admission names another release or has no reason")
	}
	if admission.IssuedAt.IsZero() || admission.IssuedAt.After(now) || !now.Before(admission.ExpiresAt) || admission.ExpiresAt.Sub(admission.IssuedAt) <= 0 || admission.ExpiresAt.Sub(admission.IssuedAt) > Lifetime {
		return "", errors.New("admission expired or exceeds its 24-hour lifetime")
	}
	for _, timestamp := range result.VerifiedTimestamps {
		if admission.IssuedAt.Before(timestamp.Timestamp.Add(-time.Minute)) || admission.IssuedAt.After(timestamp.Timestamp.Add(time.Minute)) {
			return "", errors.New("admission issuance differs from its verified signing time")
		}
	}
	return run[1], nil
}
