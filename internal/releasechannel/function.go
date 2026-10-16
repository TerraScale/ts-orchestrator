package releasechannel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

const (
	FunctionChannelSchema   = "terrascale.functions.release-channel.v1"
	FunctionChannelObject   = "releases/functions/channel.json"
	MaxFunctionEntries      = 256
	MaxFunctionChannelBytes = 1 << 20
)

// FunctionRelease carries signed provenance, never unsigned execution authority.
type FunctionRelease struct {
	Envelope   jsontext.Value `json:"envelope"`
	Delegation jsontext.Value `json:"delegation"`
}

// Claim returns untrusted selection metadata. Consumers must verify both signed
// envelopes and the module against their own roots, scope and durable floor.
func (entry FunctionRelease) Claim() (release.FunctionClaim, error) {
	envelope, err := trust.DecodeEnvelope(entry.Envelope)
	if err != nil {
		return release.FunctionClaim{}, err
	}
	if _, err := trust.DecodeEnvelope(entry.Delegation); err != nil {
		return release.FunctionClaim{}, err
	}
	var claim release.FunctionClaim
	if err := json.Unmarshal(envelope.Payload, &claim, json.RejectUnknownMembers(true)); err != nil {
		return release.FunctionClaim{}, err
	}
	if err := claim.Validate(); err != nil {
		return release.FunctionClaim{}, err
	}
	canonical, err := trust.EncodePayload(claim)
	if err != nil || !bytes.Equal(canonical, envelope.Payload) || envelope.Scope != release.FunctionScope(claim) {
		return release.FunctionClaim{}, ErrInvalid
	}
	return claim, nil
}

// FunctionChannel is an unsigned index sorted by the signed tenant/function key.
// Entries only select candidates for current release verification.
type FunctionChannel struct {
	Schema  string            `json:"schema"`
	Entries []FunctionRelease `json:"entries"`
}

func FunctionModuleObject(digest string) string { return "releases/functions/modules/" + digest }

func decodeFunctionChannel(wire []byte) (FunctionChannel, error) {
	var channel FunctionChannel
	if len(wire) > MaxFunctionChannelBytes || json.Unmarshal(wire, &channel, json.RejectUnknownMembers(true)) != nil || channel.Schema != FunctionChannelSchema || len(channel.Entries) > MaxFunctionEntries {
		return FunctionChannel{}, ErrInvalid
	}
	previous := ""
	for _, entry := range channel.Entries {
		claim, err := entry.Claim()
		if err != nil {
			return FunctionChannel{}, err
		}
		key := functionReleaseKey(claim)
		if key <= previous {
			return FunctionChannel{}, ErrInvalid
		}
		previous = key
	}
	return channel, nil
}

func functionReleaseKey(claim release.FunctionClaim) string {
	return claim.TenantID + "." + claim.FunctionID
}

func ReadFunctionChannel(ctx context.Context, location Location) (FunctionChannel, bool, error) {
	wire, _, found, err := location.get(ctx, FunctionChannelObject, MaxFunctionChannelBytes)
	if err != nil || !found {
		return FunctionChannel{}, found, err
	}
	channel, err := decodeFunctionChannel(wire)
	return channel, true, err
}

// ReadFunctionModule bounds allocation and checks the requested immutable digest.
// A module's bytes alone authorize neither its tenant nor execution.
func ReadFunctionModule(ctx context.Context, location Location, digest string) ([]byte, error) {
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != sha256.Size || digest != strings.ToLower(digest) {
		return nil, ErrInvalid
	}
	module, _, found, err := location.get(ctx, FunctionModuleObject(digest), release.MaxFunctionModuleBytes)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: function module is absent", ErrInvalid)
	}
	sum := sha256.Sum256(module)
	if len(module) == 0 || hex.EncodeToString(sum[:]) != digest {
		return nil, fmt.Errorf("%w: function module digest mismatch", ErrInvalid)
	}
	return module, nil
}

// PublishFunction uploads an already admitted module and merges its signed
// release by CAS. Other tenants survive concurrent publication unchanged.
func PublishFunction(ctx context.Context, location Location, proof release.VerifiedFunction) error {
	if !proof.Valid() || location.Client == nil || location.Namespace == "" || location.Bucket == "" {
		return ErrInvalid
	}
	claim := proof.Claim()
	expectedBucket, err := BucketName(claim.Cell)
	if err != nil || location.Bucket != expectedBucket {
		return ErrInvalid
	}
	envelope, err := trust.DecodeEnvelope(proof.Envelope())
	if err != nil {
		return err
	}
	delegation, err := trust.DecodeEnvelope(proof.Delegation())
	if err != nil {
		return err
	}
	entry := FunctionRelease{}
	entry.Envelope, err = trust.EncodeEnvelope(envelope)
	if err != nil {
		return err
	}
	entry.Delegation, err = trust.EncodeEnvelope(delegation)
	if err != nil {
		return err
	}
	module := proof.Module()
	if len(module) == 0 || len(module) > release.MaxFunctionModuleBytes {
		return ErrInvalid
	}
	// If the create reply was lost, immutable readback decides whether it succeeded.
	if err := putFunctionModule(ctx, location, claim.Digest, module); err != nil {
		readback, readErr := ReadFunctionModule(ctx, location, claim.Digest)
		if readErr != nil || !bytes.Equal(readback, module) {
			return err
		}
	}
	readback, err := ReadFunctionModule(ctx, location, claim.Digest)
	if err != nil || !bytes.Equal(readback, module) {
		return fmt.Errorf("%w: published function module readback", ErrInvalid)
	}
	key := functionReleaseKey(claim)
	for range 8 {
		if !proof.Valid() {
			return trust.ErrExpired
		}
		wire, etag, found, err := location.get(ctx, FunctionChannelObject, MaxFunctionChannelBytes)
		if err != nil {
			return err
		}
		channel := FunctionChannel{Schema: FunctionChannelSchema, Entries: []FunctionRelease{}}
		if found {
			channel, err = decodeFunctionChannel(wire)
			if err != nil {
				return err
			}
		}
		index, exists := slices.BinarySearchFunc(channel.Entries, key, func(candidate FunctionRelease, target string) int {
			current, _ := candidate.Claim()
			return strings.Compare(functionReleaseKey(current), target)
		})
		if exists {
			current, _ := channel.Entries[index].Claim()
			if current.Sequence > claim.Sequence {
				return ErrStale
			}
			if current.Sequence == claim.Sequence {
				if bytes.Equal(channel.Entries[index].Envelope, entry.Envelope) && bytes.Equal(channel.Entries[index].Delegation, entry.Delegation) {
					return nil
				}
				return fmt.Errorf("%w: function sequence already names another signed release", ErrInvalid)
			}
			channel.Entries[index] = entry
		} else {
			if len(channel.Entries) >= MaxFunctionEntries {
				return fmt.Errorf("%w: function channel exceeds %d entries", ErrInvalid, MaxFunctionEntries)
			}
			channel.Entries = slices.Insert(channel.Entries, index, entry)
		}
		next, err := json.Marshal(channel, json.Deterministic(true))
		if err != nil {
			return err
		}
		if len(next) > MaxFunctionChannelBytes {
			return fmt.Errorf("%w: function channel exceeds 1 MiB", ErrInvalid)
		}
		if !proof.Valid() {
			return trust.ErrExpired
		}
		writeErr := location.put(ctx, FunctionChannelObject, next, etag)
		if writeErr == nil {
			return nil
		}
		// A successful write can lose its reply; accept only exact provenance readback.
		current, readErr := readPublishedFunction(ctx, location, key, entry)
		if readErr == nil && current {
			return nil
		}
		if !errors.Is(writeErr, ErrConflict) {
			return writeErr
		}
	}
	return ErrConflict
}

func putFunctionModule(ctx context.Context, location Location, digest string, module []byte) error {
	name := FunctionModuleObject(digest)
	_, err := location.Client.PutObject(ctx, objectstorage.PutObjectRequest{NamespaceName: new(location.Namespace), BucketName: new(location.Bucket), ObjectName: new(name), ContentLength: new(int64(len(module))), PutObjectBody: io.NopCloser(bytes.NewReader(module)), ContentType: new("application/wasm"), IfNoneMatch: new("*")})
	if httpStatus(err) == http.StatusPreconditionFailed {
		return ErrConflict
	}
	return err
}

func readPublishedFunction(ctx context.Context, location Location, key string, expected FunctionRelease) (bool, error) {
	channel, found, err := ReadFunctionChannel(ctx, location)
	if err != nil || !found {
		return false, err
	}
	for _, entry := range channel.Entries {
		claim, _ := entry.Claim()
		if functionReleaseKey(claim) == key {
			return bytes.Equal(entry.Envelope, expected.Envelope) && bytes.Equal(entry.Delegation, expected.Delegation), nil
		}
	}
	return false, nil
}
