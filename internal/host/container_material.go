//go:build linux

package host

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

const containerMaterialDocument = "container-material.json"
const maxContainerMaterialBytes = 192 << 10

var containerMaterialID = regexp.MustCompile(`^[a-z0-9]{25}$`)
var containerMaterialSlot = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
var containerMaterialKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*_FILE$`)

// ContainerMaterialBinding contains selectors for the actual task and admitted host.
type ContainerMaterialBinding struct {
	TaskID      string `json:"task_id"`
	ServiceID   string `json:"service_id"`
	NodeID      string `json:"node_id"`
	InstanceID  string `json:"instance_id"`
	Region      string `json:"region"`
	HostID      string `json:"host_id"`
	Fingerprint string `json:"fingerprint"`
}

// ContainerMaterialFiles is one immutable, bounded task inventory. The provider
// authorizes every reference against current signed profile and container intent.
type ContainerMaterialFiles struct {
	Files               map[string][]byte `json:"files"`
	FileEnvironment     map[string]string `json:"file_environment"`
	User                string            `json:"user"`
	ExpiresAt           time.Time         `json:"expires_at"`
	CredentialExpiresAt time.Time         `json:"credential_expires_at,omitzero"`
}

type ContainerMaterialProvider func(context.Context, Registration, ContainerMaterialBinding, ContainerMaterialEvidence) (ContainerMaterialFiles, error)

type containerMaterialQuery struct {
	Binding                ContainerMaterialBinding `json:"binding"`
	RegistrationGeneration uint64                   `json:"registration_generation"`
	Offset                 int                      `json:"offset"`
	Length                 int                      `json:"length"`
	EphemeralPublicKey     []byte                   `json:"ephemeral_public_key"`
	InventoryExpiresAt     time.Time                `json:"inventory_expires_at,omitzero"`
	InventorySHA256        string                   `json:"inventory_sha256,omitempty"`
}

type containerMaterialReply struct {
	materialReply
	InventoryExpiresAt time.Time `json:"inventory_expires_at"`
}

func validContainerInventoryQuery(query containerMaterialQuery) bool {
	if query.Offset == 0 {
		return query.InventoryExpiresAt.IsZero() && query.InventorySHA256 == ""
	}
	return time.Now().Before(query.InventoryExpiresAt) && lowerHex(query.InventorySHA256, 64)
}

func validateContainerMaterialBinding(binding ContainerMaterialBinding) error {
	if !containerMaterialID.MatchString(binding.TaskID) || !containerMaterialID.MatchString(binding.ServiceID) ||
		!containerMaterialID.MatchString(binding.NodeID) || !catalog.IsOCIRegion(binding.Region) ||
		(!entityid.Valid(binding.HostID) && !containerMaterialSlot.MatchString(binding.HostID)) ||
		!strings.HasPrefix(binding.InstanceID, "ocid1.instance.") || len(binding.InstanceID) <= len("ocid1.instance.") || len(binding.InstanceID) > 255 ||
		strings.ContainsAny(binding.InstanceID, " \r\n\t") || !lowerHex(binding.Fingerprint, 64) {
		return errors.New("container material task or recipient identity is invalid")
	}
	return nil
}

func validateContainerMaterial(files ContainerMaterialFiles) error {
	uid, gid, split := strings.Cut(files.User, ":")
	u, ue := strconv.ParseUint(uid, 10, 32)
	g, ge := strconv.ParseUint(gid, 10, 32)
	if !split || ue != nil || ge != nil || u == 0 || g == 0 || !time.Now().Before(files.ExpiresAt) ||
		(!files.CredentialExpiresAt.IsZero() && (!files.CredentialExpiresAt.After(time.Now()) || files.ExpiresAt.After(files.CredentialExpiresAt))) ||
		len(files.Files) > vaultsecret.MaxRefs || len(files.Files) != len(files.FileEnvironment) {
		return errors.New("container material inventory, user or expiry is invalid")
	}
	total := 0
	seen := make(map[string]bool, len(files.Files))
	for key, name := range files.FileEnvironment {
		value, found := files.Files[name]
		if !containerMaterialKey.MatchString(key) || name != strings.ToLower(key) || path.Base(name) != name ||
			!found || seen[name] || len(value) == 0 || len(value) > 64<<10 {
			return errors.New("container material requires distinct signed file environment bindings")
		}
		total += len(value)
		seen[name] = true
	}
	if total > 96<<10 {
		return errors.New("container material exceeds the bounded secret inventory")
	}
	return nil
}

func clearContainerMaterial(files ContainerMaterialFiles) {
	for _, value := range files.Files {
		clear(value)
	}
}

func (c *Controller) serveContainerMaterial(ctx context.Context, req request, registration Registration, current session) (any, error) {
	ctx, cancel := context.WithDeadline(ctx, (ContainerMaterialEvidence{Request: req.Envelope}).Deadline())
	defer cancel()
	if c.containerMaterial == nil || c.authorityEpoch == nil || registration.Generation != current.RegistrationGeneration || registration.Node != req.Node {
		return nil, errors.New("container material authority is pending for this host")
	}
	var query containerMaterialQuery
	if err := decodeStrict(req.Payload, &query); err != nil {
		return nil, err
	}
	region, known := catalog.CellForOCIRegion(query.Binding.Region)
	if validateContainerMaterialBinding(query.Binding) != nil || !known || region.Name() != c.cell ||
		query.RegistrationGeneration != registration.Generation || query.Offset < 0 || query.Offset >= maxContainerMaterialBytes ||
		query.Length < 1 || query.Length > materialChunkBytes || len(query.EphemeralPublicKey) != 32 || !validContainerInventoryQuery(query) {
		return nil, errors.New("container material request differs from the current host or bounds")
	}
	epoch := c.authorityEpoch()
	if err := c.guard(ctx, epoch); err != nil {
		return nil, err
	}
	files, err := c.containerMaterial(ctx, registration, query.Binding, ContainerMaterialEvidence{Request: req.Envelope})
	if err != nil {
		return nil, err
	}
	defer clearContainerMaterial(files)
	ctx, materialCancel := context.WithDeadline(ctx, files.ExpiresAt)
	defer materialCancel()
	if err := validateContainerMaterial(files); err != nil {
		return nil, err
	}
	if query.Offset > 0 && !files.ExpiresAt.Equal(query.InventoryExpiresAt) {
		return nil, errors.New("container material inventory deadline changed; restart inventory")
	}
	wire, err := protocol.EncodeJSON(files)
	if err != nil {
		return nil, err
	}
	defer clear(wire)
	if len(wire) > maxContainerMaterialBytes || query.Offset >= len(wire) {
		return nil, errors.New("container material inventory is oversized or chunk is out of bounds")
	}
	if sum := sha256.Sum256(wire); query.Offset > 0 && hex.EncodeToString(sum[:]) != query.InventorySHA256 {
		return nil, errors.New("container material inventory changed; restart inventory")
	}
	latest, err := c.registration(ctx, req.Node)
	if err != nil || !sameJSON(registration, latest) {
		return nil, errors.New("container material host registration changed")
	}
	active, _, exists, err := c.sessionSnapshot(ctx, sessionKey(c.cell, req.Node))
	if err != nil {
		return nil, err
	}
	if !exists || !currentAuthorizedSession(active, latest, req, time.Now()) || !time.Now().Before(files.ExpiresAt) {
		return nil, errors.New("container material host session or inventory expired")
	}
	if err := c.guard(ctx, epoch); err != nil {
		return nil, err
	}
	aad, err := materialAAD(req, query)
	if err != nil {
		return nil, err
	}
	end := min(len(wire), query.Offset+query.Length)
	reply, err := encryptHostMaterialChunk(aad, query.EphemeralPublicKey, containerMaterialDocument, query.Offset, wire[query.Offset:end], len(wire), wire)
	if ctx.Err() != nil || !time.Now().Before(files.ExpiresAt) {
		return nil, errors.New("container material deadline expired before encryption completed")
	}
	return containerMaterialReply{materialReply: reply, InventoryExpiresAt: files.ExpiresAt}, err
}

// CurrentContainerFiles uses the existing authenticated ownhost session; neither
// secret values nor Vault references are sent in an unencrypted reply.
func (a *Agent) CurrentContainerFiles(ctx context.Context, binding ContainerMaterialBinding) (result ContainerMaterialFiles, resultErr error) {
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
			clearContainerMaterial(result)
			result = ContainerMaterialFiles{}
		}
	}()
	total, digest := 0, ""
	var inventoryExpiresAt time.Time
	for total == 0 || len(wire) < total {
		if _, _, err := a.executionLease(); err != nil {
			return result, err
		}
		private, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return result, err
		}
		query := containerMaterialQuery{Binding: binding, RegistrationGeneration: current.RegistrationGeneration,
			Offset: len(wire), Length: materialChunkBytes, EphemeralPublicKey: private.PublicKey().Bytes(),
			InventoryExpiresAt: inventoryExpiresAt, InventorySHA256: digest}
		var reply containerMaterialReply
		req, err := a.sendToLeader(ctx, "container-material", query, &reply, nil, nil)
		if err != nil {
			return result, err
		}
		if reply.File != containerMaterialDocument || reply.Offset != query.Offset || reply.Total < 1 || reply.Total > maxContainerMaterialBytes ||
			!lowerHex(reply.SHA256, 64) || len(reply.EphemeralPublicKey) != 32 || len(reply.Nonce) != 12 ||
			!time.Now().Before(reply.InventoryExpiresAt) || total != 0 && (reply.Total != total || reply.SHA256 != digest || !reply.InventoryExpiresAt.Equal(inventoryExpiresAt)) {
			return result, errors.New("container material encrypted inventory changed")
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
			return result, errors.New("container material chunk cannot be authenticated")
		}
		wire = append(wire, chunk...)
		clear(chunk)
		total, digest = reply.Total, reply.SHA256
		inventoryExpiresAt = reply.InventoryExpiresAt
	}
	sum := sha256.Sum256(wire)
	if hex.EncodeToString(sum[:]) != digest {
		return result, errors.New("container material digest changed")
	}
	if err := protocol.DecodeStrict(wire, &result, maxContainerMaterialBytes); err != nil {
		return result, errors.New("container material inventory cannot be decoded")
	}
	if err := validateContainerMaterial(result); err != nil {
		return result, err
	}
	if !result.ExpiresAt.Equal(inventoryExpiresAt) {
		return result, errors.New("container material inventory deadline cannot be authenticated")
	}
	if _, _, err := a.executionLease(); err != nil {
		return result, err
	}
	return result, nil
}
