package initialgrant

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/preliminarycapture"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
)

// VerifyPreliminaryUpload binds an upload to the original owner's admitted
// source launch. Historical capture authority may have expired; both the
// initial admission and the upload authorization must still be live.
func (a *Admission) VerifyPreliminaryUpload(ctx context.Context, raw []byte) (preliminarytransfer.VerifiedUpload, error) {
	if err := a.Check(ctx); err != nil {
		return preliminarytransfer.VerifiedUpload{}, err
	}
	if a.proof == nil || a.proof.config.Role != "seed" || a.proof.config.PreliminaryCapture == nil || a.proof.config.PreliminaryCapture.Publication == nil {
		return preliminarytransfer.VerifiedUpload{}, errors.New("initialgrant: source publication is not admitted")
	}
	verified, err := preliminarytransfer.VerifyUploadRequest(a.proof.public, raw, time.Now().UTC())
	if err != nil {
		return preliminarytransfer.VerifiedUpload{}, err
	}
	scope, auth := verified.Scope.Scope, verified.Authorization
	identity, cfg := a.proof.identity, a.proof.config
	capture := cfg.PreliminaryCapture
	if scope.SourceNodeID != identity.NodeID || scope.InitialGrantSHA256 != identity.GrantSHA256 || scope.StoreScopeSHA256 != identity.StoreScopeSHA256 || scope.ProfileSHA256 != cfg.ProfileSHA256 || scope.MaxSnapshotBytes > capture.MaxSnapshotBytes || scope.MaxTotalBytes > capture.MaxTotalBytes || auth.IssuedAt.Before(identity.IssuedAt) || auth.ExpiresAt.After(identity.ExpiresAt) {
		return preliminarytransfer.VerifiedUpload{}, errors.New("initialgrant: publication differs from admitted source or bounds")
	}
	membership, err := base64.StdEncoding.Strict().DecodeString(cfg.Membership.PublicKey)
	source, rest := pem.Decode([]byte(scope.SourcePublicKeyPEM))
	if err != nil || source == nil || source.Type != "PUBLIC KEY" || len(rest) != 0 || !bytes.Equal(source.Bytes, membership) {
		return preliminarytransfer.VerifiedUpload{}, errors.New("initialgrant: capture receipt signer differs from admitted membership key")
	}
	historical, err := preliminarycapture.VerifyRequest(a.proof.public, scope.CaptureRequest)
	if err != nil {
		return preliminarytransfer.VerifiedUpload{}, err
	}
	request := historical.Request
	if request.SourceNodeID != identity.NodeID || request.InitialGrantSHA256 != identity.GrantSHA256 || request.StoreScopeSHA256 != identity.StoreScopeSHA256 || request.ProfileSHA256 != cfg.ProfileSHA256 || request.IssuedAt.Before(identity.IssuedAt) || request.ExpiresAt.After(identity.ExpiresAt) || len(request.Accounts) != 2 || cfg.Global == nil || request.Accounts[0].Account != cfg.Regional.Account || request.Accounts[1].Account != cfg.Global.Account {
		return preliminarytransfer.VerifiedUpload{}, errors.New("initialgrant: historical capture differs from admitted source")
	}
	if err := a.Check(ctx); err != nil {
		return preliminarytransfer.VerifiedUpload{}, err
	}
	return verified, nil
}

// ReadPreliminaryUpload applies the root-owned descriptor protections used for
// capture requests, with the larger signed transfer-document bound.
func ReadPreliminaryUpload(path string) ([]byte, error) {
	return readRootRequest(path, preliminarytransfer.MaximumBytes)
}
