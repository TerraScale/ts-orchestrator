//go:build linux

package host

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

const registryAdmissionDocument = "registry-admission.json"
const maxRegistryAdmissionBytes = 192 << 10

// RegistryAdmissionDocument carries only original signed delivery intent and
// independently adopted service metadata; credentials never enter this document.
type RegistryAdmissionDocument struct {
	Document  []byte    `json:"document"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RegistryAdmissionProvider authenticates the actual manager assignment, signed
// release, adopted profile and durable ordering floor for this registered host.
type RegistryAdmissionProvider func(context.Context, Registration, ContainerMaterialBinding) (RegistryAdmissionDocument, error)

type registryAdmissionQuery struct {
	Binding                ContainerMaterialBinding `json:"binding"`
	RegistrationGeneration uint64                   `json:"registration_generation"`
	Offset                 int                      `json:"offset"`
	Length                 int                      `json:"length"`
	EphemeralPublicKey     []byte                   `json:"ephemeral_public_key"`
}

func validateRegistryAdmission(document RegistryAdmissionDocument) error {
	if len(document.Document) == 0 || len(document.Document) > 128<<10 || !time.Now().Before(document.ExpiresAt) || document.ExpiresAt.After(time.Now().Add(2*time.Minute)) {
		return errors.New("registry admission document is missing, oversized or expired")
	}
	return nil
}

func (c *Controller) serveRegistryAdmission(ctx context.Context, req request, registration Registration, current session) (any, error) {
	if c.registryAdmission == nil || c.authorityEpoch == nil || registration.Generation != current.RegistrationGeneration || registration.Node != req.Node {
		return nil, errors.New("registry admission authority is pending for this host")
	}
	var query registryAdmissionQuery
	if err := decodeStrict(req.Payload, &query); err != nil {
		return nil, err
	}
	region, known := catalog.CellForOCIRegion(query.Binding.Region)
	if validateContainerMaterialBinding(query.Binding) != nil || !known || region.Name() != c.cell ||
		query.Binding.HostID != registration.ID || query.RegistrationGeneration != registration.Generation || query.Offset < 0 || query.Offset >= maxRegistryAdmissionBytes ||
		query.Length < 1 || query.Length > materialChunkBytes || len(query.EphemeralPublicKey) != 32 {
		return nil, errors.New("registry admission request differs from the current host or bounds")
	}
	epoch := c.authorityEpoch()
	if err := c.guard(ctx, epoch); err != nil {
		return nil, err
	}
	files, err := c.registryAdmission(ctx, registration, query.Binding)
	if err != nil {
		return nil, err
	}
	defer clear(files.Document)
	if err := validateRegistryAdmission(files); err != nil {
		return nil, err
	}
	wire, err := protocol.EncodeJSON(files)
	if err != nil {
		return nil, err
	}
	defer clear(wire)
	if len(wire) > maxRegistryAdmissionBytes || query.Offset >= len(wire) {
		return nil, errors.New("registry admission inventory is oversized or chunk is out of bounds")
	}
	latest, err := c.registration(ctx, req.Node)
	if err != nil || !sameJSON(registration, latest) {
		return nil, errors.New("registry admission host registration changed")
	}
	active, _, exists, err := c.sessionSnapshot(ctx, sessionKey(c.cell, req.Node))
	if err != nil {
		return nil, err
	}
	if !exists || !currentAuthorizedSession(active, latest, req, time.Now()) || !time.Now().Before(files.ExpiresAt) {
		return nil, errors.New("registry admission host session or inventory expired")
	}
	if err := c.guard(ctx, epoch); err != nil {
		return nil, err
	}
	aad, err := materialAAD(req, query)
	if err != nil {
		return nil, err
	}
	end := min(len(wire), query.Offset+query.Length)
	return encryptHostMaterialChunk(aad, query.EphemeralPublicKey, registryAdmissionDocument, query.Offset, wire[query.Offset:end], len(wire), wire)
}

// CurrentRegistryAdmission retrieves admission through the existing signed host
// session, with every chunk encrypted for its exact request.
func (a *Agent) CurrentRegistryAdmission(ctx context.Context, binding ContainerMaterialBinding) (result RegistryAdmissionDocument, resultErr error) {
	if err := validateContainerMaterialBinding(binding); err != nil {
		return result, err
	}
	if a.sessionLost.Load() {
		return result, errors.New("host session was lost")
	}
	current, _, err := a.executionLease()
	if err != nil {
		return result, err
	}
	var wire []byte
	defer func() {
		clear(wire)
		if resultErr != nil {
			clear(result.Document)
			result = RegistryAdmissionDocument{}
		}
	}()
	total, digest := 0, ""
	for total == 0 || len(wire) < total {
		if _, _, err := a.executionLease(); err != nil {
			return result, err
		}
		private, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return result, err
		}
		query := registryAdmissionQuery{Binding: binding, RegistrationGeneration: current.RegistrationGeneration,
			Offset: len(wire), Length: materialChunkBytes, EphemeralPublicKey: private.PublicKey().Bytes()}
		var reply materialReply
		req, err := a.sendToLeader(ctx, "registry-admission", query, &reply, nil, nil)
		if err != nil {
			return result, err
		}
		if reply.File != registryAdmissionDocument || reply.Offset != query.Offset || reply.Total < 1 || reply.Total > maxRegistryAdmissionBytes ||
			!lowerHex(reply.SHA256, 64) || len(reply.EphemeralPublicKey) != 32 || len(reply.Nonce) != 12 ||
			total != 0 && (reply.Total != total || reply.SHA256 != digest) {
			return result, errors.New("registry admission encrypted inventory changed")
		}
		public, err := ecdh.X25519().NewPublicKey(reply.EphemeralPublicKey)
		if err != nil {
			return result, err
		}
		shared, err := private.ECDH(public)
		if err != nil {
			return result, err
		}
		aad, err := materialAAD(req, query)
		if err != nil {
			clear(shared)
			return result, err
		}
		aead, err := materialAEAD(shared, aad)
		clear(shared)
		if err != nil {
			return result, err
		}
		chunk, err := aead.Open(nil, reply.Nonce, reply.Ciphertext, aad)
		if err != nil || len(chunk) == 0 || len(chunk) > query.Length || len(wire)+len(chunk) > reply.Total {
			clear(chunk)
			return result, errors.New("registry admission chunk cannot be authenticated")
		}
		wire = append(wire, chunk...)
		clear(chunk)
		total, digest = reply.Total, reply.SHA256
	}
	sum := sha256.Sum256(wire)
	if hex.EncodeToString(sum[:]) != digest {
		return result, errors.New("registry admission digest changed")
	}
	if err := protocol.DecodeStrict(wire, &result, maxRegistryAdmissionBytes); err != nil {
		return result, errors.New("registry admission inventory cannot be decoded")
	}
	if err := validateRegistryAdmission(result); err != nil {
		return result, err
	}
	if _, _, err := a.executionLease(); err != nil {
		return result, err
	}
	return result, nil
}
