// Package captureplan signs finite requests for source-owned preliminary
// snapshots. Planning opens no broker and does not authorize a final cut.
package captureplan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/initialcontrol"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarycapture"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

type planInput struct {
	OwnerPrivateKeyFile      string    `json:"ownerPrivateKeyFile"`
	PublicKeyFile            string    `json:"publicKeyFile"`
	SourceNodeID             string    `json:"sourceNodeId"`
	SourceBootstrapGrantFile string    `json:"sourceBootstrapGrantFile"`
	TransitionID             string    `json:"transitionId"`
	ControlEpoch             uint64    `json:"controlEpoch"`
	IssuedAt                 time.Time `json:"issuedAt"`
	ExpiresAt                time.Time `json:"expiresAt"`
}
type publicBundle struct {
	PublicKeyPEM string          `json:"publicKeyPem"`
	Request      json.RawMessage `json:"request"`
}

// Run verifies the original owner-signed seed launch and emits only public
// bindings and a signed request. The source worker independently checks its
// durable admission, exact inventory and live epoch before capture.
func Run(ctx context.Context, path string, output io.Writer) error {
	bad := errors.New("capture plan: invalid protected input, owner identity or finite source binding")
	if ctx == nil || output == nil {
		return bad
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := bootstrapcredentials.ReadFile(path, true, preliminarycapture.MaximumBytes)
	if err != nil {
		return bad
	}
	defer clear(raw)
	var input planInput
	if err := decodeInput(raw, &input); err != nil {
		return bad
	}
	public, err := bootstrapcredentials.ReadFile(input.PublicKeyFile, false, 32<<10)
	if err != nil {
		return bad
	}
	signedSource, err := bootstrapcredentials.ReadFile(input.SourceBootstrapGrantFile, true, 2<<20)
	if err != nil {
		return bad
	}
	defer clear(signedSource)
	proof, err := initialgrant.VerifyProof(input.SourceNodeID, public, signedSource)
	if err != nil || proof == nil {
		return bad
	}
	cfg, identity := proof.Config(), proof.Identity()
	if cfg.Role != "seed" || cfg.PreliminaryCapture == nil || cfg.Global == nil {
		return bad
	}
	now := time.Now().UTC()
	if now.Before(identity.IssuedAt) || !now.Before(identity.ExpiresAt) || input.IssuedAt.Before(identity.IssuedAt) || input.ExpiresAt.After(identity.ExpiresAt) || now.Before(input.IssuedAt) || !now.Before(input.ExpiresAt) {
		return bad
	}
	profile, err := initialcontrol.ProfileDigest(cfg.Cell, cfg.SeedInstance)
	if err != nil || profile != cfg.ProfileSHA256 {
		return bad
	}
	accounts, err := initialcontrol.PreliminaryInventory(cfg.Cell, cfg.SeedInstance, cfg.Regional.Account, cfg.Global.Account)
	if err != nil {
		return bad
	}
	request := preliminarycapture.Request{Version: 1, TransitionID: input.TransitionID, SourceNodeID: identity.NodeID, InitialGrantSHA256: identity.GrantSHA256, StoreScopeSHA256: identity.StoreScopeSHA256, ProfileSHA256: profile, Accounts: accounts, ControlEpoch: input.ControlEpoch, IssuedAt: input.IssuedAt, ExpiresAt: input.ExpiresAt}
	if _, err := preliminarycapture.CanonicalRequest(request); err != nil {
		return bad
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
	signed, err := preliminarycapture.SignRequest(signer, request)
	if err != nil {
		return bad
	}
	verified, err := preliminarycapture.VerifyRequest(public, signed)
	if err != nil || verified.Check(time.Now().UTC()) != nil {
		return bad
	}
	encoded, err := json.Marshal(publicBundle{PublicKeyPEM: string(public), Request: signed})
	if err != nil {
		return bad
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if n, err := output.Write(encoded); err != nil || n != len(encoded) {
		return errors.New("capture plan: could not write public bundle")
	}
	return nil
}

// Input is deliberately flat. Exact key matching rejects duplicate, unknown,
// differently cased or null fields before Go's permissive struct decoder runs.
func decodeInput(raw []byte, out *planInput) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return errors.New("capture plan: object required")
	}
	allowed := map[string]bool{"ownerPrivateKeyFile": true, "publicKeyFile": true, "sourceNodeId": true, "sourceBootstrapGrantFile": true, "transitionId": true, "controlEpoch": true, "issuedAt": true, "expiresAt": true}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok || !allowed[name] || seen[name] {
			return errors.New("capture plan: invalid field")
		}
		seen[name] = true
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("capture plan: invalid value")
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || len(seen) != len(allowed) {
		return errors.New("capture plan: incomplete input")
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("capture plan: trailing input")
	}
	return json.Unmarshal(raw, out)
}
