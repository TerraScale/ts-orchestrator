// Package transferplan plans public owner-signed transfer authorizations from
// original source/candidate grants and a completed source capture receipt.
package transferplan

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialcontrol"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/nodebootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarycapture"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
)

type planInput struct {
	OwnerPrivateKeyFile       string                            `json:"ownerPrivateKeyFile"`
	PublicKeyFile             string                            `json:"publicKeyFile"`
	SourceNodeID              string                            `json:"sourceNodeId"`
	SourceBootstrapGrantFile  string                            `json:"sourceBootstrapGrantFile"`
	CaptureRequestFile        string                            `json:"captureRequestFile"`
	CaptureReceiptFile        string                            `json:"captureReceiptFile"`
	PreparationGrantFile      string                            `json:"preparationGrantFile"`
	Candidates                []candidateInput                  `json:"candidates"`
	Prefix                    string                            `json:"prefix"`
	Destinations              []preliminarytransfer.Destination `json:"destinations"`
	MaxSnapshotBytes          int64                             `json:"maxSnapshotBytes"`
	MaxTotalBytes             int64                             `json:"maxTotalBytes"`
	MaxRestoreBytes           int64                             `json:"maxRestoreBytes"`
	UploadControlEpoch        uint64                            `json:"uploadControlEpoch"`
	UploadIssuedAt            time.Time                         `json:"uploadIssuedAt"`
	UploadExpiresAt           time.Time                         `json:"uploadExpiresAt"`
	CandidateIssuedAt         time.Time                         `json:"candidateIssuedAt"`
	CandidateExpiresAt        time.Time                         `json:"candidateExpiresAt"`
	PreviousUploadRequestFile string                            `json:"previousUploadRequestFile,omitempty"`
}
type candidateInput struct {
	NodeID             string `json:"nodeId"`
	BootstrapGrantFile string `json:"bootstrapGrantFile"`
}
type candidateOutput struct {
	NodeID  string          `json:"nodeId"`
	Request json.RawMessage `json:"request"`
}
type publicBundle struct {
	PublicKeyPEM  string            `json:"publicKeyPem"`
	ScopeSHA256   string            `json:"scopeSha256"`
	Scope         json.RawMessage   `json:"scope"`
	UploadRequest json.RawMessage   `json:"uploadRequest"`
	Candidates    []candidateOutput `json:"candidates"`
}

func Run(ctx context.Context, path string, output io.Writer) error {
	bad := errors.New("transfer plan: invalid protected input, original admission or immutable capture binding")
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
	if decodeInput(raw, &input) != nil {
		return bad
	}
	public, err := bootstrapcredentials.ReadFile(input.PublicKeyFile, false, 32<<10)
	if err != nil {
		return bad
	}
	sourceSigned, err := bootstrapcredentials.ReadFile(input.SourceBootstrapGrantFile, true, 2<<20)
	if err != nil {
		return bad
	}
	defer clear(sourceSigned)
	proof, err := initialgrant.VerifyProof(input.SourceNodeID, public, sourceSigned)
	if err != nil || proof == nil {
		return bad
	}
	cfg, identity := proof.Config(), proof.Identity()
	now := time.Now().UTC()
	if cfg.Role != "seed" || cfg.PreliminaryCapture == nil || cfg.PreliminaryCapture.Publication == nil || cfg.Global == nil || now.Before(identity.IssuedAt) || !now.Before(identity.ExpiresAt) || input.UploadIssuedAt.Before(identity.IssuedAt) || input.UploadExpiresAt.After(identity.ExpiresAt) {
		return bad
	}
	profile, err := initialcontrol.ProfileDigest(cfg.Cell, cfg.SeedInstance)
	if err != nil || profile != cfg.ProfileSHA256 {
		return bad
	}
	if input.MaxSnapshotBytes > cfg.PreliminaryCapture.MaxSnapshotBytes || input.MaxTotalBytes > cfg.PreliminaryCapture.MaxTotalBytes {
		return bad
	}
	der, err := base64.StdEncoding.DecodeString(cfg.Membership.PublicKey)
	if err != nil {
		return bad
	}
	sourcePublic := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	requestSigned, err := bootstrapcredentials.ReadFile(input.CaptureRequestFile, true, preliminarycapture.MaximumBytes)
	if err != nil {
		return bad
	}
	receiptSigned, err := bootstrapcredentials.ReadFile(input.CaptureReceiptFile, true, preliminarycapture.MaximumBytes)
	if err != nil {
		return bad
	}
	request, err := preliminarycapture.VerifyRequest(public, requestSigned)
	if err != nil {
		return bad
	}
	receipt, err := preliminarycapture.VerifyReceipt(sourcePublic, receiptSigned)
	if err != nil {
		return bad
	}
	r := request.Request
	inventory, err := initialcontrol.PreliminaryInventory(cfg.Cell, cfg.SeedInstance, cfg.Regional.Account, cfg.Global.Account)
	if err != nil {
		return bad
	}
	got, _ := json.Marshal(r.Accounts)
	want, _ := json.Marshal(inventory)
	if r.SourceNodeID != identity.NodeID || r.InitialGrantSHA256 != identity.GrantSHA256 || r.StoreScopeSHA256 != identity.StoreScopeSHA256 || r.ProfileSHA256 != profile || !bytes.Equal(got, want) || r.IssuedAt.Before(identity.IssuedAt) || r.ExpiresAt.After(identity.ExpiresAt) {
		return bad
	}
	preparationSigned, err := bootstrapcredentials.ReadFile(input.PreparationGrantFile, true, transitiongrant.MaximumBytes)
	if err != nil {
		return bad
	}
	preparation, err := transitiongrant.VerifyGrant(public, preparationSigned)
	if err != nil {
		return bad
	}
	g := preparation.Grant
	if g.TransitionID != r.TransitionID || g.Source.NodeID != identity.NodeID || g.Source.InitialGrantSHA256 != identity.GrantSHA256 || g.Source.StoreScopeSHA256 != identity.StoreScopeSHA256 || g.Source.ServerName != cfg.Broker.ServerName || input.CandidateIssuedAt.Before(g.IssuedAt) || input.CandidateExpiresAt.After(g.ExpiresAt) || now.Before(g.IssuedAt) || !now.Before(g.ExpiresAt) {
		return bad
	}
	scope := preliminarytransfer.Scope{Version: 1, TransitionID: r.TransitionID, SourceNodeID: identity.NodeID, InitialGrantSHA256: identity.GrantSHA256, StoreScopeSHA256: identity.StoreScopeSHA256, ProfileSHA256: profile, SourcePublicKeyPEM: string(sourcePublic), CaptureRequest: requestSigned, CaptureReceipt: receiptSigned, RequestSHA256: request.Digest, ReceiptSHA256: preliminarytransfer.Digest(receiptSigned), PreparationGrantSHA256: preparation.Digest, Prefix: input.Prefix, Destinations: input.Destinations, MaxSnapshotBytes: input.MaxSnapshotBytes, MaxTotalBytes: input.MaxTotalBytes, MaxRestoreBytes: input.MaxRestoreBytes}
	if len(input.Candidates) != 2 {
		return bad
	}
	for i, entry := range input.Candidates {
		signed, err := bootstrapcredentials.ReadFile(entry.BootstrapGrantFile, true, 2<<20)
		if err != nil {
			return bad
		}
		candidate, err := deriveCandidate(entry.NodeID, public, signed, preparation, now)
		clear(signed)
		if err != nil || candidate.Region != []string{"sfo", "fra"}[i] {
			return bad
		}
		if candidate.sync.MaxSnapshotBytes < input.MaxSnapshotBytes || candidate.sync.MaxTotalBytes < input.MaxTotalBytes || candidate.sync.MaxRestoreBytes < input.MaxRestoreBytes {
			return bad
		}
		scope.Candidates = append(scope.Candidates, candidate.Candidate)
	}
	for _, d := range scope.Destinations {
		for _, o := range receipt.Objects {
			scope.Objects = append(scope.Objects, preliminarytransfer.ObjectMapping{Region: d.Region, Account: o.Account, Stream: o.Stream, LocalKey: o.Key, ObjectKey: scope.Prefix + "/" + scope.RequestSHA256 + "/" + o.Key, SHA256: o.SHA256, Size: o.Size})
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
	signedScope, err := preliminarytransfer.SignScope(signer, scope)
	if err != nil {
		return bad
	}
	verified, err := preliminarytransfer.VerifyScope(public, signedScope)
	if err != nil {
		return bad
	}
	uploadAuth, err := preliminarytransfer.SignUploadAuthorization(signer, preliminarytransfer.UploadAuthorization{Version: 1, ScopeSHA256: verified.Digest, ControlEpoch: input.UploadControlEpoch, IssuedAt: input.UploadIssuedAt, ExpiresAt: input.UploadExpiresAt})
	if err != nil {
		return bad
	}
	uploadRaw, err := preliminarytransfer.MarshalRequest(signedScope, uploadAuth)
	if err != nil {
		return bad
	}
	upload, err := preliminarytransfer.VerifyUploadRequest(public, uploadRaw, now)
	if err != nil {
		return bad
	}
	if input.PreviousUploadRequestFile != "" {
		priorRaw, err := bootstrapcredentials.ReadFile(input.PreviousUploadRequestFile, true, preliminarytransfer.MaximumBytes)
		if err != nil {
			return bad
		}
		var priorWire preliminarytransfer.Request
		var priorEnvelope struct {
			Payload preliminarytransfer.UploadAuthorization `json:"payload"`
		}
		if json.Unmarshal(priorRaw, &priorWire) != nil || json.Unmarshal(priorWire.Authorization, &priorEnvelope) != nil {
			return bad
		}
		prior, err := preliminarytransfer.VerifyUploadRequest(public, priorRaw, priorEnvelope.Payload.IssuedAt)
		if err != nil || preliminarytransfer.CheckUploadRenewal(prior, upload) != nil {
			return bad
		}
	}
	bundle := publicBundle{PublicKeyPEM: string(public), ScopeSHA256: verified.Digest, Scope: signedScope, UploadRequest: uploadRaw}
	for _, c := range scope.Candidates {
		auth, err := preliminarytransfer.SignCandidateAuthorization(signer, preliminarytransfer.CandidateAuthorization{Version: 1, ScopeSHA256: verified.Digest, NodeID: c.NodeID, IssuedAt: input.CandidateIssuedAt, ExpiresAt: input.CandidateExpiresAt})
		if err != nil {
			return bad
		}
		raw, err := preliminarytransfer.MarshalRequest(signedScope, auth)
		if err != nil {
			return bad
		}
		if _, err := preliminarytransfer.VerifyCandidateRequest(public, raw, now); err != nil {
			return bad
		}
		bundle.Candidates = append(bundle.Candidates, candidateOutput{c.NodeID, raw})
	}
	// Recheck finite authority after all protected reads and signing. A slow
	// filesystem must not let a plan emit authorizations that have since expired.
	finalNow := time.Now().UTC()
	if upload.Check(finalNow) != nil {
		return bad
	}
	for _, candidate := range bundle.Candidates {
		if _, err := preliminarytransfer.VerifyCandidateRequest(public, candidate.Request, finalNow); err != nil {
			return bad
		}
	}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		return bad
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if n, err := output.Write(encoded); err != nil || n != len(encoded) {
		return errors.New("transfer plan: could not write public bundle")
	}
	return nil
}

type admittedCandidate struct {
	preliminarytransfer.Candidate
	sync *transitiongrant.CandidateSyncConfig
}

func deriveCandidate(node string, public, signed []byte, preparation transitiongrant.VerifiedGrant, now time.Time) (admittedCandidate, error) {
	bad := errors.New("transfer plan: original candidate admission differs")
	original, err := nodebootstrap.NewBootstrapAuthority(node, public, signed)
	if err != nil {
		return admittedCandidate{}, bad
	}
	manifest, err := hostmanifest.ParseHostManifest(original.Grant().Manifest)
	if err != nil {
		return admittedCandidate{}, bad
	}
	var cfg transitiongrant.Config
	found := false
	for _, component := range manifest.Components {
		c, yes, err := transitiongrant.ComponentConfig(component)
		if err != nil {
			return admittedCandidate{}, bad
		}
		if yes {
			if found {
				return admittedCandidate{}, bad
			}
			cfg, found = c, true
		}
	}
	if !found || cfg.Sync == nil {
		return admittedCandidate{}, bad
	}
	peer, err := bootstrap.PlanControlCandidatePeer(cfg, public, signed)
	if err != nil {
		return admittedCandidate{}, bad
	}
	if preparation.CheckCandidate(now, cfg, peer.BootstrapGrantSHA256, peer.PreparedManifestSHA256) != nil {
		return admittedCandidate{}, bad
	}
	return admittedCandidate{Candidate: preliminarytransfer.Candidate{Region: peer.Region, NodeID: peer.NodeID, ServerName: peer.ServerName, BootstrapGrantSHA256: peer.BootstrapGrantSHA256, ManifestSHA256: peer.PreparedManifestSHA256, ReceiptPublicKeyPEM: cfg.Sync.ReceiptPublicKeyPEM}, sync: cfg.Sync}, nil
}
