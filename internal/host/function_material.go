//go:build linux

package host

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
)

var functionMaterialNames = [...]string{
	"deployment.json", "module.wasm", "receipt.json", "delegation.json", "root.pub",
	"broker.creds", "broker-ca.pem", "ingress-cert.pem", "ingress-key.pem", "ingress-ca.pem",
}

type functionMaterialQuery struct {
	Binding                FunctionMaterialBinding `json:"binding"`
	RegistrationGeneration uint64                  `json:"registration_generation"`
	File                   string                  `json:"file"`
	Offset                 int                     `json:"offset"`
	Length                 int                     `json:"length"`
	EphemeralPublicKey     []byte                  `json:"ephemeral_public_key"`
}

type functionMaterialReply struct {
	materialReply
	ExpiresAt      time.Time `json:"expires_at"`
	ManifestSHA256 string    `json:"manifest_sha256"`
}

func validateFunctionMaterialBinding(binding FunctionMaterialBinding) error {
	return (authority.FunctionBinding{TaskID: binding.TaskID, ServiceID: binding.ServiceID, NodeID: binding.NodeID,
		InstanceID: binding.InstanceID, Region: binding.Region, HostID: binding.HostID, Fingerprint: binding.Fingerprint,
		MaterialManifestSHA256: binding.Fingerprint}).Validate()
}

func functionMaterialLimit(name string) int {
	switch name {
	case "module.wasm":
		return release.MaxFunctionModuleBytes
	case "root.pub":
		return 32
	case "deployment.json":
		return 16 << 10
	default:
		return 64 << 10
	}
}

func functionMaterialChunkSize(name string) int {
	if name == "module.wasm" {
		return artifactChunkBytes
	}
	return materialChunkBytes
}

func functionMaterialDigest(files map[string][]byte, expires time.Time) (string, error) {
	if len(files) != len(functionMaterialNames) || !time.Now().Before(expires) {
		return "", errors.New("function material inventory is incomplete or expired")
	}
	type fileDigest struct {
		Name   string `json:"name"`
		Bytes  int    `json:"bytes"`
		SHA256 string `json:"sha256"`
	}
	inventory := make([]fileDigest, 0, len(files))
	for _, name := range functionMaterialNames {
		content := files[name]
		if len(content) == 0 || len(content) > functionMaterialLimit(name) {
			return "", errors.New("function material file is missing or oversized")
		}
		digest := sha256.Sum256(content)
		inventory = append(inventory, fileDigest{Name: name, Bytes: len(content), SHA256: hex.EncodeToString(digest[:])})
	}
	wire, err := protocol.EncodeJSON(struct {
		Files     []fileDigest `json:"files"`
		ExpiresAt time.Time    `json:"expires_at"`
	}{inventory, expires})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:]), nil
}

func (c *Controller) serveFunctionMaterial(ctx context.Context, req request, registration Registration, currentSession session) (any, error) {
	if c.functionMaterial == nil || c.authorityEpoch == nil || registration.Generation != currentSession.RegistrationGeneration ||
		registration.Node != req.Node || !slices.Contains(registration.Roles, "function-worker") {
		return nil, errors.New("function material delivery is unavailable for this host")
	}
	var query functionMaterialQuery
	if err := decodeStrict(req.Payload, &query); err != nil {
		return nil, err
	}
	region, known := catalog.CellForOCIRegion(query.Binding.Region)
	if validateFunctionMaterialBinding(query.Binding) != nil || !known || region.Name() != c.cell ||
		query.Binding.HostID != registration.ID || query.RegistrationGeneration != registration.Generation ||
		!slices.Contains(functionMaterialNames[:], query.File) || query.Offset < 0 ||
		query.Offset >= functionMaterialLimit(query.File) || query.Length < 1 || query.Length > functionMaterialChunkSize(query.File) ||
		len(query.EphemeralPublicKey) != 32 {
		return nil, errors.New("function material query differs from the registered host or file bounds")
	}
	epoch := c.authorityEpoch()
	if err := c.guard(ctx, epoch); err != nil {
		return nil, err
	}
	material, err := c.functionMaterial(ctx, registration, query.Binding)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, content := range material.Files {
			clear(content)
		}
	}()
	manifest, err := functionMaterialDigest(material.Files, material.ExpiresAt)
	if err != nil {
		return nil, err
	}
	contents := material.Files[query.File]
	if query.Offset >= len(contents) {
		return nil, errors.New("function material chunk starts past the file")
	}
	latest, err := c.registration(ctx, req.Node)
	if err != nil || !sameJSON(registration, latest) {
		return nil, errors.New("function material host registration changed")
	}
	session, _, exists, err := c.sessionSnapshot(ctx, sessionKey(c.cell, req.Node))
	if err != nil {
		return nil, err
	}
	if !exists || !currentAuthorizedSession(session, latest, req, time.Now()) || !time.Now().Before(material.ExpiresAt) {
		return nil, errors.New("function material session or delivery expired")
	}
	if err := c.guard(ctx, epoch); err != nil {
		return nil, err
	}
	aad, err := materialAAD(req, query)
	if err != nil {
		return nil, err
	}
	end := min(len(contents), query.Offset+query.Length)
	chunk, err := encryptHostMaterialChunk(aad, query.EphemeralPublicKey, query.File, query.Offset,
		contents[query.Offset:end], len(contents), contents)
	if err != nil {
		return nil, err
	}
	return functionMaterialReply{materialReply: chunk, ExpiresAt: material.ExpiresAt, ManifestSHA256: manifest}, nil
}

// CurrentFunctionFiles retrieves one exact task's verified inventory over the
// existing signed host session. Every chunk is encrypted for this request.
func (a *Agent) CurrentFunctionFiles(ctx context.Context, binding FunctionMaterialBinding) (files map[string][]byte, expires time.Time, resultErr error) {
	if err := validateFunctionMaterialBinding(binding); err != nil {
		return nil, time.Time{}, err
	}
	if a.sessionLost.Load() {
		return nil, time.Time{}, errors.New("host session was lost")
	}
	session, _, err := a.executionLease()
	if err != nil {
		return nil, time.Time{}, err
	}
	files = make(map[string][]byte, len(functionMaterialNames))
	defer func() {
		if resultErr != nil {
			for _, content := range files {
				clear(content)
			}
			files = nil
		}
	}()
	manifest := ""
	for _, name := range functionMaterialNames {
		content, currentManifest, currentExpiry, err := a.downloadFunctionFile(ctx, binding, session.RegistrationGeneration, name, manifest, expires)
		if err != nil {
			return files, time.Time{}, fmt.Errorf("retrieve function material %s: %w", name, err)
		}
		files[name], manifest, expires = content, currentManifest, currentExpiry
	}
	actual, err := functionMaterialDigest(files, expires)
	if err != nil || actual != manifest {
		return files, time.Time{}, errors.New("function material inventory changed during delivery")
	}
	if _, _, err := a.executionLease(); err != nil {
		return files, time.Time{}, err
	}
	return files, expires, nil
}

func (a *Agent) downloadFunctionFile(ctx context.Context, binding FunctionMaterialBinding, generation uint64,
	name, manifest string, expires time.Time,
) (contents []byte, currentManifest string, currentExpiry time.Time, resultErr error) {
	defer func() {
		if resultErr != nil {
			clear(contents)
		}
	}()
	var digest string
	total := 0
	for total == 0 || len(contents) < total {
		if _, _, err := a.executionLease(); err != nil {
			return contents, "", time.Time{}, err
		}
		private, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return contents, "", time.Time{}, err
		}
		query := functionMaterialQuery{Binding: binding, RegistrationGeneration: generation,
			File: name, Offset: len(contents), Length: functionMaterialChunkSize(name), EphemeralPublicKey: private.PublicKey().Bytes()}
		var reply functionMaterialReply
		req, err := a.sendToLeader(ctx, "function-material", query, &reply, nil, nil)
		if err != nil {
			return contents, "", time.Time{}, err
		}
		if reply.File != name || reply.Offset != query.Offset || reply.Total < 1 || reply.Total > functionMaterialLimit(name) ||
			!lowerHex(reply.SHA256, 64) || !lowerHex(reply.ManifestSHA256, 64) || !time.Now().Before(reply.ExpiresAt) ||
			len(reply.EphemeralPublicKey) != 32 || len(reply.Nonce) != 12 ||
			total != 0 && (reply.Total != total || reply.SHA256 != digest) ||
			manifest != "" && (reply.ManifestSHA256 != manifest || !reply.ExpiresAt.Equal(expires)) {
			return contents, "", time.Time{}, errors.New("function material chunk identity changed")
		}
		public, err := ecdh.X25519().NewPublicKey(reply.EphemeralPublicKey)
		if err != nil {
			return contents, "", time.Time{}, err
		}
		shared, err := private.ECDH(public)
		if err != nil {
			return contents, "", time.Time{}, err
		}
		aad, err := materialAAD(req, query)
		if err != nil {
			clear(shared)
			return contents, "", time.Time{}, err
		}
		aead, err := materialAEAD(shared, aad)
		clear(shared)
		if err != nil {
			return contents, "", time.Time{}, err
		}
		chunk, err := aead.Open(nil, reply.Nonce, reply.Ciphertext, aad)
		if err != nil || len(chunk) == 0 || len(chunk) > query.Length || len(contents)+len(chunk) > reply.Total {
			clear(chunk)
			return contents, "", time.Time{}, errors.New("function material chunk cannot be authenticated")
		}
		contents = append(contents, chunk...)
		clear(chunk)
		total, digest = reply.Total, reply.SHA256
		manifest, expires = reply.ManifestSHA256, reply.ExpiresAt
	}
	sum := sha256.Sum256(contents)
	if hex.EncodeToString(sum[:]) != digest {
		return contents, "", time.Time{}, errors.New("function material file digest changed")
	}
	return contents, manifest, expires, nil
}
