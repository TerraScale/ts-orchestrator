// Package storageplan prepares the owner's signed R1-to-R3 transition document.
// It verifies historical admission and preliminary evidence without host effects.
package storageplan

import (
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
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := bootstrapcredentials.ReadFile(path, true, 2<<20)
	if err != nil {
		return bad
	}
	defer clear(raw)
	var input planInput
	if json.Unmarshal(raw, &input, json.RejectUnknownMembers(true)) != nil || input.Plan.Validate() != nil || len(input.DestinationBootstrapGrantFiles) != 3 || len(input.CandidateReceiptFiles) != 2 {
		return bad
	}
	public, err := bootstrapcredentials.ReadFile(input.PublicKeyFile, false, 4096)
	if err != nil {
		return bad
	}
	source, err := bootstrapcredentials.ReadFile(input.SourceBootstrapGrantFile, true, 2<<20)
	if err != nil {
		return bad
	}
	defer clear(source)
	for i, d := range input.Plan.Destinations {
		signed, err := bootstrapcredentials.ReadFile(input.DestinationBootstrapGrantFiles[i], true, 2<<20)
		if err != nil {
			return bad
		}
		err = verifyDestination(public, signed, input.Plan.Source, d)
		clear(signed)
		if err != nil {
			return bad
		}
	}
	scopeRaw, err := bootstrapcredentials.ReadFile(input.PreliminaryScopeFile, true, preliminarytransfer.MaximumBytes)
	if err != nil {
		return bad
	}
	scope, err := preliminarytransfer.VerifyScope(public, scopeRaw)
	if err != nil {
		return bad
	}
	if verifySource(public, source, input.Plan, scope) != nil {
		return bad
	}
	receipts := make([][]byte, 2)
	for i, path := range input.CandidateReceiptFiles {
		receipts[i], err = bootstrapcredentials.ReadFile(path, true, preliminarytransfer.MaximumBytes)
		if err != nil {
			return bad
		}
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
	signed, err := controltransition.SignPlan(signer, input.Plan)
	if err != nil {
		return bad
	}
	plan, err := controltransition.VerifyPlan(public, signed)
	if err != nil {
		return bad
	}
	if _, err = candidatesync.VerifyTransitionCandidates(plan, scope, receipts, time.Now()); err != nil {
		return bad
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := plan.Check(time.Now()); err != nil {
		return bad
	}
	if n, err := output.Write(signed); err != nil || n != len(signed) {
		return errors.New("storage plan: could not write signed plan")
	}
	return nil
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
