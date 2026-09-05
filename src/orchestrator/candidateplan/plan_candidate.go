package candidateplan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"reflect"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/nodebootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
	"terrascale.tech/orchestrator/src/orchestrator/vmcandidateseed"
)

type candidatePlanInput struct {
	PrivateMaterialDirectory string               `json:"privateMaterialDirectory,omitempty"`
	OwnerPrivateKeyFile      string               `json:"ownerPrivateKeyFile"`
	PublicKeyFile            string               `json:"publicKeyFile"`
	SourceNodeID             string               `json:"sourceNodeId"`
	SourceBootstrapGrantFile string               `json:"sourceBootstrapGrantFile"`
	TargetEpoch              uint64               `json:"targetEpoch"`
	MinimumControlEpoch      uint64               `json:"minimumControlEpoch"`
	TransitionID             string               `json:"transitionId"`
	IssuedAt                 time.Time            `json:"issuedAt"`
	ExpiresAt                time.Time            `json:"expiresAt"`
	BootstrapExpiresAt       time.Time            `json:"bootstrapExpiresAt"`
	Candidates               []candidatePlanEntry `json:"candidates"`
}
type candidatePlanEntry struct {
	SyncGeneration   *vmcandidateseed.Declaration `json:"syncGeneration,omitempty"`
	Manifest         hostmanifest.HostManifest    `json:"manifest"`
	Config           transitiongrant.Config       `json:"config"`
	BootstrapGrantID string                       `json:"bootstrapGrantId"`
}
type candidatePlanBundle struct {
	PublicKeyPEM     string                `json:"publicKeyPem"`
	PreparationGrant json.RawMessage       `json:"preparationGrant"`
	Candidates       []candidatePlanOutput `json:"candidates"`
}
type candidatePlanOutput struct {
	NodeID         string          `json:"nodeId"`
	Manifest       json.RawMessage `json:"manifest"`
	BootstrapGrant json.RawMessage `json:"bootstrapGrant"`
}

// Run emits public preparation artifacts only. The owner
// signs the exact candidate manifests first, then the separate transition grant.
func Run(ctx context.Context, path string, output io.Writer) error {
	bad := errors.New("candidate plan: invalid protected input, owner identity or finite preparation binding")
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
	var input candidatePlanInput
	if err := decodeCandidatePlan(raw, &input); err != nil {
		return bad
	}
	if len(input.Candidates) != 2 {
		return bad
	}
	canonicalInput, err := json.Marshal(input)
	if err != nil {
		return bad
	}
	defer clear(canonicalInput)
	now := time.Now().UTC()
	if input.IssuedAt.IsZero() || now.Before(input.IssuedAt) || !now.Before(input.ExpiresAt) || !input.BootstrapExpiresAt.After(input.IssuedAt) || input.BootstrapExpiresAt.After(input.ExpiresAt) || !now.Before(input.BootstrapExpiresAt) {
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
	planHash := sha256.New()
	_, _ = planHash.Write(canonicalInput)
	_, _ = planHash.Write(public)
	_, _ = planHash.Write(sourceSigned)
	planSHA256 := hex.EncodeToString(planHash.Sum(nil))
	proof, err := initialgrant.VerifyProof(input.SourceNodeID, public, sourceSigned)
	if err != nil || proof == nil || proof.Config().Role != "seed" {
		return bad
	}
	source, err := nodebootstrap.NewBootstrapAuthority(input.SourceNodeID, public, sourceSigned)
	if err != nil {
		return bad
	}
	identity := proof.Identity()
	if now.Before(identity.IssuedAt) || !now.Before(identity.ExpiresAt) {
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
	ownerBlock, _ := pem.Decode(public)
	if ownerBlock == nil {
		return bad
	}
	ownerSum := sha256.Sum256(ownerBlock.Bytes)
	if signer.PublicKeyID() != hex.EncodeToString(ownerSum[:]) {
		return bad
	}
	sourceConfig := proof.Config()
	grant := transitiongrant.Grant{Version: 1, TransitionID: input.TransitionID, IssuedAt: input.IssuedAt, ExpiresAt: input.ExpiresAt, TargetEpoch: input.TargetEpoch, MinimumControlEpoch: input.MinimumControlEpoch, Source: transitiongrant.SourceIdentity{NodeID: input.SourceNodeID, ServerName: sourceConfig.Broker.ServerName, InitialGrantSHA256: source.Digest(), StoreScopeSHA256: identity.StoreScopeSHA256}, Peers: []transitiongrant.Peer{{Region: "gru", NodeID: input.SourceNodeID, ServerName: sourceConfig.Broker.ServerName, BootstrapGrantSHA256: source.Digest(), PreparedManifestSHA256: identity.ManifestSHA256}}}
	bundle := candidatePlanBundle{PublicKeyPEM: string(public)}
	for i, region := range []string{"sfo", "fra"} {
		if err := ctx.Err(); err != nil {
			return err
		}
		entry := input.Candidates[i]
		if entry.Config.Region != region || entry.Config.TransitionID != input.TransitionID {
			return bad
		}
		if entry.SyncGeneration != nil {
			if input.PrivateMaterialDirectory == "" {
				return bad
			}
			material, err := vmcandidateseed.Generate(input.PrivateMaterialDirectory, entry.Config, *entry.SyncGeneration, planSHA256)
			if err != nil {
				return err
			}
			entry.Config = material.Config
			input.Candidates[i].Config = material.Config
			material.Clear()
		} else if input.PrivateMaterialDirectory != "" {
			return bad
		}
		manifest, err := bootstrap.PlanControlCandidateManifest(entry.Manifest, entry.Config)
		if err != nil {
			return bad
		}
		manifestJSON, err := hostmanifest.CanonicalHostManifestJSON(manifest)
		if err != nil {
			return bad
		}
		signed, err := nodebootstrap.SignBootstrapGrant(signer, nodebootstrap.BootstrapGrant{Version: 1, GrantID: entry.BootstrapGrantID, NodeID: entry.Config.NodeID, Manifest: manifestJSON, IssuedAt: input.IssuedAt, ExpiresAt: input.BootstrapExpiresAt})
		if err != nil {
			return bad
		}
		// Verification with the source's owner public key also rejects a mismatched
		// private signing credential before any output is emitted.
		peer, err := bootstrap.PlanControlCandidatePeer(entry.Config, public, signed)
		if err != nil {
			return bad
		}
		grant.Peers = append(grant.Peers, peer)
		bundle.Candidates = append(bundle.Candidates, candidatePlanOutput{NodeID: entry.Config.NodeID, Manifest: manifestJSON, BootstrapGrant: signed})
	}
	signed, err := transitiongrant.SignGrant(signer, grant)
	if err != nil {
		return bad
	}
	verified, err := transitiongrant.VerifyGrant(public, signed)
	if err != nil {
		return bad
	}
	for i, entry := range input.Candidates {
		peer := grant.Peers[i+1]
		if err := verified.CheckCandidate(time.Now().UTC(), entry.Config, peer.BootstrapGrantSHA256, peer.PreparedManifestSHA256); err != nil {
			return bad
		}
	}
	bundle.PreparationGrant = signed
	encoded, err := json.Marshal(bundle)
	if err != nil {
		return bad
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if input.PrivateMaterialDirectory != "" {
		encoded, err = vmcandidateseed.PersistBundle(input.PrivateMaterialDirectory, planSHA256, encoded)
		if err != nil {
			return err
		}
	}
	encoded = append(encoded, '\n')
	if n, err := output.Write(encoded); err != nil || n != len(encoded) {
		return errors.New("candidate plan: could not write public bundle")
	}
	return nil
}

func decodeCandidatePlan(raw []byte, out *candidatePlanInput) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var scan func(int) error
	scan = func(depth int) error {
		if depth > 32 {
			return errors.New("candidate plan: JSON nesting exceeds bound")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if token == nil {
			return errors.New("candidate plan: null input")
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("candidate plan: duplicate field")
				}
				seen[name] = true
				if err := scan(depth + 1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("candidate plan: malformed object")
			}
		case json.Delim('['):
			for decoder.More() {
				if err := scan(depth + 1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("candidate plan: malformed array")
			}
		}
		return nil
	}
	if err := scan(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("candidate plan: trailing JSON")
	}
	if err := candidatePlanKnownFields(raw, reflect.TypeOf(*out)); err != nil {
		return err
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(out)
}

// encoding/json accepts case-insensitive aliases for struct fields. Admission
// accepts only the schema's exact JSON names, including nested component data.
func candidatePlanKnownFields(raw []byte, typ reflect.Type) error {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if reflect.PointerTo(typ).Implements(reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()) {
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return err
		}
		allowed := map[string]reflect.Type{}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name != "" && name != "-" {
				allowed[name] = field.Type
			}
		}
		for name, value := range fields {
			field, ok := allowed[name]
			if !ok {
				return errors.New("candidate plan: unknown field")
			}
			if err := candidatePlanKnownFields(value, field); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		var values []json.RawMessage
		if err := json.Unmarshal(raw, &values); err != nil {
			return err
		}
		for _, value := range values {
			if err := candidatePlanKnownFields(value, typ.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}
