// Package storageplan prepares the owner's signed R1-to-R3 transition document.
// It verifies historical admission and preliminary evidence without host effects.
package storageplan

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"io"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/candidatesync"
	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/nodebootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

type planInput struct {
	OwnerPrivateKeyFile            string                 `json:"ownerPrivateKeyFile"`
	PublicKeyFile                  string                 `json:"publicKeyFile"`
	SourceBootstrapGrantFile       string                 `json:"sourceBootstrapGrantFile"`
	DestinationBootstrapGrantFiles []string               `json:"destinationBootstrapGrantFiles"`
	PreliminaryScopeFile           string                 `json:"preliminaryScopeFile"`
	CandidateReceiptFiles          []string               `json:"candidateReceiptFiles"`
	Plan                           controltransition.Plan `json:"plan"`
}

// Run writes the exact canonical signed plan, with no trailing newline. Retain
// these bytes: signing the same input again produces a different plan identity.
func Run(ctx context.Context, path string, output io.Writer) error {
	bad := errors.New("storage plan: invalid protected input or transition evidence")
	if ctx == nil || output == nil {
		return bad
	}
	raw, err := bootstrapcredentials.ReadFile(path, true, 2<<20)
	if err != nil {
		return bad
	}
	defer clear(raw)
	var input planInput
	if json.Unmarshal(raw, &input, json.RejectUnknownMembers(true)) != nil || len(input.DestinationBootstrapGrantFiles) != 3 || len(input.CandidateReceiptFiles) != 2 {
		return bad
	}
	public, err := bootstrapcredentials.ReadFile(input.PublicKeyFile, false, 4096)
	if err != nil {
		return bad
	}
	evidence := Evidence{}
	evidence.Source, err = bootstrapcredentials.ReadFile(input.SourceBootstrapGrantFile, true, 2<<20)
	if err != nil {
		return bad
	}
	for _, path := range input.DestinationBootstrapGrantFiles {
		raw, err := bootstrapcredentials.ReadFile(path, true, 2<<20)
		if err != nil {
			return bad
		}
		evidence.Destinations = append(evidence.Destinations, raw)
	}
	evidence.PreliminaryScope, err = bootstrapcredentials.ReadFile(input.PreliminaryScopeFile, true, preliminarytransfer.MaximumBytes)
	if err != nil {
		return bad
	}
	for _, path := range input.CandidateReceiptFiles {
		raw, err := bootstrapcredentials.ReadFile(path, true, preliminarytransfer.MaximumBytes)
		if err != nil {
			return bad
		}
		evidence.CandidateReceipts = append(evidence.CandidateReceipts, raw)
	}
	private, err := bootstrapcredentials.ReadFile(input.OwnerPrivateKeyFile, true, 32<<10)
	if err != nil {
		return bad
	}
	signer, err := security.ParseCommandSignatureSignerPEM(private)
	clear(private)
	if err != nil {
		return bad
	}
	defer signer.Close()
	signed, err := Prepare(ctx, input.Plan, evidence, public, signer)
	if err != nil {
		return err
	}
	if n, err := output.Write(signed); err != nil || n != len(signed) {
		return errors.New("storage plan: could not write signed plan")
	}
	return nil
}

// Evidence is the original immutable admission and actual preliminary capture
// output. Neither file names nor declared digest strings replace these bytes.
type Evidence struct {
	Source            []byte
	Destinations      [][]byte
	PreliminaryScope  []byte
	CandidateReceipts [][]byte
}

func verifyEvidence(expected controltransition.Plan, evidence Evidence, public []byte) (preliminarytransfer.VerifiedScope, error) {
	bad := errors.New("storage plan: original evidence differs from immutable transition intent")
	if expected.Validate() != nil || len(evidence.Destinations) != 3 || len(evidence.CandidateReceipts) != 2 || len(public) > 4096 || len(evidence.Source) > 2<<20 || len(evidence.PreliminaryScope) > preliminarytransfer.MaximumBytes {
		return preliminarytransfer.VerifiedScope{}, bad
	}
	for index, destination := range expected.Destinations {
		if len(evidence.Destinations[index]) > 2<<20 || verifyDestination(public, evidence.Destinations[index], expected.Source, destination) != nil {
			return preliminarytransfer.VerifiedScope{}, bad
		}
	}
	scope, err := preliminarytransfer.VerifyScope(public, evidence.PreliminaryScope)
	if err != nil || verifySource(public, evidence.Source, expected, scope) != nil {
		return preliminarytransfer.VerifiedScope{}, bad
	}
	for _, receipt := range evidence.CandidateReceipts {
		if len(receipt) > preliminarytransfer.MaximumBytes {
			return preliminarytransfer.VerifiedScope{}, bad
		}
	}
	return scope, nil
}

// Prepare is shared by the CLI and persisted live issuer. It signs only after
// original source/destination grants and actual preliminary scope are verified.
func Prepare(ctx context.Context, plan controltransition.Plan, evidence Evidence, public []byte, signer *security.CommandSignatureSigner) ([]byte, error) {
	if ctx == nil || signer == nil {
		return nil, errors.New("storage plan: signing context required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := verifyEvidence(plan, evidence, public); err != nil {
		return nil, err
	}
	signed, err := controltransition.SignPlan(signer, plan)
	if err != nil {
		return nil, err
	}
	if _, err := Verify(ctx, plan, evidence, public, signed); err != nil {
		return nil, err
	}
	return signed, nil
}

// Verify admits an existing signed plan on restart without issuing a new
// signature. Every original grant and actual candidate receipt is rechecked.
func Verify(ctx context.Context, expected controltransition.Plan, evidence Evidence, public, signed []byte) (controltransition.VerifiedPlan, error) {
	if ctx == nil {
		return controltransition.VerifiedPlan{}, errors.New("storage plan: verification context required")
	}
	if err := ctx.Err(); err != nil {
		return controltransition.VerifiedPlan{}, err
	}
	scope, err := verifyEvidence(expected, evidence, public)
	if err != nil {
		return controltransition.VerifiedPlan{}, err
	}
	plan, err := controltransition.VerifyPlan(public, signed)
	if err != nil {
		return controltransition.VerifiedPlan{}, err
	}
	actual, err := plan.Plan()
	if err != nil {
		return controltransition.VerifiedPlan{}, err
	}
	wanted, _ := json.Marshal(expected, json.Deterministic(true))
	got, _ := json.Marshal(actual, json.Deterministic(true))
	if !bytes.Equal(wanted, got) {
		return controltransition.VerifiedPlan{}, errors.New("storage plan: persisted plan differs from requested immutable intent")
	}
	if _, err := candidatesync.VerifyTransitionCandidates(plan, scope, evidence.CandidateReceipts, time.Now()); err != nil {
		return controltransition.VerifiedPlan{}, err
	}
	if err := plan.Check(time.Now()); err != nil {
		return controltransition.VerifiedPlan{}, err
	}
	return plan, nil
}

func verifySource(public, signed []byte, p controltransition.Plan, scope preliminarytransfer.VerifiedScope) error {
	bad := errors.New("storage plan: original source admission differs")
	proof, err := initialgrant.VerifyProof(p.Source.NodeID, public, signed)
	if err != nil || proof == nil {
		return bad
	}
	identity, config := proof.Identity(), proof.Config()
	membership, err := base64.StdEncoding.DecodeString(config.Membership.PublicKey)
	if err != nil {
		return bad
	}
	captureKey, err := preliminarytransfer.PublicKeyID([]byte(scope.Scope.SourcePublicKeyPEM))
	if err != nil || captureKey != controltransition.Digest(membership) {
		return bad
	}
	capture, err := scope.HistoricalCapture()
	if err != nil || capture.Request.IssuedAt.Before(identity.IssuedAt) || capture.Request.ExpiresAt.After(identity.ExpiresAt) {
		return bad
	}
	s := p.Source
	if config.Role != "seed" || config.Global == nil || identity.GrantSHA256 != s.BootstrapGrantSHA256 || identity.ManifestSHA256 != s.InitialManifestSHA256 || identity.LaunchSHA256 != s.LaunchSHA256 || identity.StoreScopeSHA256 != s.StoreScopeSHA256 || config.ProfileSHA256 != s.ProfileSHA256 || config.Broker.ServerName != s.ServerName || config.Broker.StoreDir != s.StoreDir || p.Accounts[0].SourceName != config.Global.Account || p.Accounts[1].SourceName != config.Regional.Account {
		return bad
	}
	return nil
}

func verifyDestination(public, signed []byte, source controltransition.Source, d controltransition.Destination) error {
	bad := errors.New("storage plan: original destination admission differs")
	authority, err := nodebootstrap.NewBootstrapAuthority(d.NodeID, public, signed)
	if err != nil || authority.Digest() != d.BootstrapGrantSHA256 {
		return bad
	}
	manifest, err := hostmanifest.ParseHostManifest(authority.Grant().Manifest)
	if err != nil {
		return bad
	}
	digest, err := hostmanifest.HostManifestSha256(manifest)
	if err != nil {
		return bad
	}
	// A shared source/GRU host has an initial source manifest. Its future
	// destination preparation is separately named by the signed plan.
	expected := d.PreparedManifestSHA256
	if d.NodeID == source.NodeID {
		expected = source.InitialManifestSHA256
	}
	if digest != expected {
		return bad
	}
	return nil
}
