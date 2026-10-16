package release

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

var (
	ErrSequenceConflict          = errors.New("release sequence changed concurrently")
	ErrSequenceMigrationRequired = errors.New("release sequence requires an explicit signed migration")
)

// SequenceObject is shared by every producer of a role/environment. Only the
// release signer principal may write this object; regional apply cannot do so.
func SequenceObject(role, environment string) string {
	return "releases/sequences/" + environment + "/" + role + ".json"
}

// SequenceReservationObject retains an allocation independently of later heads.
func SequenceReservationObject(role, environment, migration string, sequence uint64) string {
	return fmt.Sprintf("releases/sequences/%s/%s/%s/%d.json", environment, role, migration, sequence)
}

type SequenceObjectClient interface {
	GetObject(context.Context, objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error)
	PutObject(context.Context, objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error)
}

type SequenceLocation struct {
	Client    SequenceObjectClient
	Namespace string
	Bucket    string
}

type SequenceIdentity struct {
	Role           string `json:"role"`
	Environment    string `json:"environment"`
	SourceRevision string `json:"source_revision"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

func (identity SequenceIdentity) validate() error {
	if !sequenceRole.MatchString(identity.Role) || validateEnvironment(identity.Environment) != nil || !ValidSourceRevision(identity.SourceRevision) || !digestPattern.MatchString(identity.ManifestSHA256) {
		return fmt.Errorf("%w: sequence allocation identity", ErrInvalidReceipt)
	}
	return nil
}

type sequenceReservation struct {
	Sequence uint64           `json:"sequence"`
	Identity SequenceIdentity `json:"identity"`
}

func sequenceReservationScope(role, environment string) trust.Scope {
	scope := SequenceMigrationScope(role, environment)
	scope.Domain = "terrascale.release.sequence-reservation"
	scope.Slot = "reservation"
	return scope
}

type sequenceHead struct {
	Schema      string           `json:"schema"`
	Sequence    uint64           `json:"sequence"`
	Identity    SequenceIdentity `json:"identity"`
	Migration   trust.Envelope   `json:"migration"`
	Reservation trust.Envelope   `json:"reservation"`
}

// Allocate reserves the next durable sequence before signing. A retry of the
// current reservation reuses it; abandoned reservations leave safe gaps.
func (location SequenceLocation) Allocate(ctx context.Context, identity SequenceIdentity, roots trust.Keyring, signer ed25519.PrivateKey) (uint64, error) {
	head, err := location.allocate(ctx, identity, roots, signer)
	return head.Sequence, err
}

// AllocateWithEvidence retains the exact winning reservation before any worker
// claim can be signed. A crash before retention leaves an unused sequence gap.
func (location SequenceLocation) AllocateWithEvidence(ctx context.Context, identity SequenceIdentity, roots trust.Keyring, signer ed25519.PrivateKey) (uint64, []byte, error) {
	head, err := location.allocate(ctx, identity, roots, signer)
	if err != nil {
		return 0, nil, err
	}
	wire, err := location.retainReservation(ctx, head, roots)
	if err != nil {
		return 0, nil, err
	}
	return head.Sequence, wire, nil
}

func (location SequenceLocation) allocate(ctx context.Context, identity SequenceIdentity, roots trust.Keyring, signer ed25519.PrivateKey) (sequenceHead, error) {
	if err := identity.validate(); err != nil {
		return sequenceHead{}, err
	}
	for range 32 {
		head, etag, found, err := location.read(ctx, identity.Role, identity.Environment, roots)
		if err != nil {
			return sequenceHead{}, err
		}
		if !found {
			return sequenceHead{}, ErrSequenceMigrationRequired
		}
		migration, err := VerifySequenceMigrationHistorical(head.Migration, roots, identity.Role, identity.Environment)
		if err != nil {
			return sequenceHead{}, err
		}
		if len(signer) != ed25519.PrivateKeySize {
			return sequenceHead{}, trust.ErrKeyMismatch
		}
		signerID, err := trust.KeyID(signer.Public().(ed25519.PublicKey))
		if err != nil || signerID != migration.SignerKeyID {
			return sequenceHead{}, trust.ErrKeyMismatch
		}
		if head.Identity == identity {
			return head, nil
		}
		if head.Sequence == math.MaxUint64 {
			return sequenceHead{}, fmt.Errorf("%w: sequence exhausted", ErrInvalidReceipt)
		}
		head.Sequence++
		head.Identity = identity
		payload, err := trust.EncodePayload(sequenceReservation{Sequence: head.Sequence, Identity: identity})
		if err != nil {
			return sequenceHead{}, err
		}
		now := time.Now().UTC()
		head.Reservation, err = trust.Sign(payload, sequenceReservationScope(identity.Role, identity.Environment), now, now.Add(MaxReceiptLifetime), signer)
		if err != nil {
			return sequenceHead{}, err
		}
		if err := location.write(ctx, identity.Role, identity.Environment, head, etag); errors.Is(err, ErrSequenceConflict) {
			continue
		} else if err != nil {
			return sequenceHead{}, err
		}
		return head, nil
	}
	return sequenceHead{}, ErrSequenceConflict
}

// ImportMigration creates the ordering namespace once. A different migration
// never overwrites an allocated sequence or an earlier migration.
func (location SequenceLocation) ImportMigration(ctx context.Context, envelope trust.Envelope, roots trust.Keyring, role, environment string, now time.Time) error {
	migration, err := VerifySequenceMigrationCurrent(envelope, roots, role, environment, now)
	if err != nil {
		return err
	}
	if migration.Namespace != location.Namespace || migration.Bucket != location.Bucket {
		return fmt.Errorf("%w: migration sequence location", ErrInvalidReceipt)
	}
	head, etag, found, err := location.read(ctx, role, environment, roots)
	if err != nil {
		return err
	}
	if found {
		existing, _ := trust.Fingerprint(head.Migration)
		incoming, _ := trust.Fingerprint(envelope)
		if existing == incoming {
			return nil
		}
		return fmt.Errorf("%w: namespace already migrated", ErrSequenceConflict)
	}
	return location.write(ctx, role, environment, sequenceHead{Schema: "terrascale.release.sequence.v1", Sequence: migration.SequenceFloor, Migration: envelope}, etag)
}

func (location SequenceLocation) read(ctx context.Context, role, environment string, roots trust.Keyring) (sequenceHead, string, bool, error) {
	var head sequenceHead
	if location.Client == nil || location.Namespace == "" || location.Bucket == "" {
		return head, "", false, fmt.Errorf("%w: sequence location", ErrInvalidReceipt)
	}
	name := SequenceObject(role, environment)
	response, err := location.Client.GetObject(ctx, objectstorage.GetObjectRequest{NamespaceName: &location.Namespace, BucketName: &location.Bucket, ObjectName: &name})
	if sequenceHTTPStatus(err) == http.StatusNotFound {
		return head, "", false, nil
	}
	if err != nil {
		return head, "", false, err
	}
	defer response.Content.Close()
	wire, err := io.ReadAll(io.LimitReader(response.Content, trust.MaxEnvelopeBytes+1))
	if err != nil {
		return head, "", false, err
	}
	head, err = verifySequenceHead(wire, roots, role, environment)
	if err != nil {
		return head, "", false, err
	}
	migration, err := VerifySequenceMigrationHistorical(head.Migration, roots, role, environment)
	if err != nil {
		return head, "", false, err
	}
	if migration.Namespace != location.Namespace || migration.Bucket != location.Bucket || response.ETag == nil || *response.ETag == "" {
		return head, "", false, fmt.Errorf("%w: migration sequence location or ETag", ErrInvalidReceipt)
	}
	return head, *response.ETag, true, nil
}

func (location SequenceLocation) write(ctx context.Context, role, environment string, head sequenceHead, etag string) error {
	wire, err := json.Marshal(head, json.Deterministic(true))
	if err != nil {
		return err
	}
	name := SequenceObject(role, environment)
	request := objectstorage.PutObjectRequest{NamespaceName: &location.Namespace, BucketName: &location.Bucket, ObjectName: &name, ContentLength: new(int64(len(wire))), PutObjectBody: io.NopCloser(bytes.NewReader(wire)), ContentType: new("application/json")}
	if etag == "" {
		request.IfNoneMatch = new("*")
	} else {
		request.IfMatch = &etag
	}
	_, err = location.Client.PutObject(ctx, request)
	if sequenceHTTPStatus(err) == http.StatusPreconditionFailed {
		return ErrSequenceConflict
	}
	return err
}

func sequenceHTTPStatus(err error) int {
	if service, ok := errors.AsType[interface {
		error
		GetHTTPStatusCode() int
	}](err); ok {
		return service.GetHTTPStatusCode()
	}
	return 0
}

func verifySequenceHead(wire []byte, roots trust.Keyring, role, environment string) (sequenceHead, error) {
	var head sequenceHead
	if err := protocol.DecodeStrict(wire, &head, trust.MaxEnvelopeBytes); err != nil {
		return head, err
	}
	migration, err := VerifySequenceMigrationHistorical(head.Migration, roots, role, environment)
	if err != nil {
		return head, err
	}
	if head.Schema != "terrascale.release.sequence.v1" || head.Sequence < migration.SequenceFloor {
		return head, fmt.Errorf("%w: sequence head", ErrInvalidReceipt)
	}
	if head.Identity != (SequenceIdentity{}) {
		if err := head.Identity.validate(); err != nil {
			return head, err
		}
		if head.Identity.Role != role || head.Identity.Environment != environment || head.Sequence == migration.SequenceFloor {
			return head, fmt.Errorf("%w: sequence identity scope", ErrInvalidReceipt)
		}
	} else if head.Sequence != migration.SequenceFloor {
		return head, fmt.Errorf("%w: missing sequence identity", ErrInvalidReceipt)
	}
	if head.Identity != (SequenceIdentity{}) {
		public, _ := base64.RawURLEncoding.Strict().DecodeString(migration.SignerPublicKey)
		payload, err := trust.VerifyHistorical(head.Reservation, sequenceReservationScope(role, environment), trust.Keyring{migration.SignerKeyID: ed25519.PublicKey(public)}, trust.Policy{MaxLifetime: MaxReceiptLifetime})
		if err != nil {
			return head, err
		}
		reservation, err := decodeCanonicalPayload[sequenceReservation](payload)
		if err != nil {
			return head, err
		}
		if reservation.Sequence != head.Sequence || reservation.Identity != head.Identity {
			return head, fmt.Errorf("%w: unauthenticated sequence head", ErrInvalidReceipt)
		}
	}
	return head, nil
}

func (location SequenceLocation) retainReservation(ctx context.Context, head sequenceHead, roots trust.Keyring) ([]byte, error) {
	wire, err := json.Marshal(head, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	if len(wire) > MaxWorkerFamilyEvidenceBytes {
		return nil, fmt.Errorf("%w: sequence evidence size", ErrInvalidReceipt)
	}
	migration, err := trust.Fingerprint(head.Migration)
	if err != nil {
		return nil, err
	}
	name := SequenceReservationObject(head.Identity.Role, head.Identity.Environment, migration, head.Sequence)
	_, err = location.Client.PutObject(ctx, objectstorage.PutObjectRequest{NamespaceName: &location.Namespace, BucketName: &location.Bucket, ObjectName: &name, ContentLength: new(int64(len(wire))), PutObjectBody: io.NopCloser(bytes.NewReader(wire)), ContentType: new("application/json"), IfNoneMatch: new("*")})
	if err == nil {
		return wire, nil
	}
	if sequenceHTTPStatus(err) != http.StatusPreconditionFailed {
		return nil, err
	}
	response, err := ociclient.ReadObject(ctx, location.Client, objectstorage.GetObjectRequest{NamespaceName: &location.Namespace, BucketName: &location.Bucket, ObjectName: &name})
	if err != nil {
		return nil, err
	}
	if response.Content == nil {
		return nil, fmt.Errorf("%w: retained sequence reservation has no body", ErrInvalidReceipt)
	}
	defer response.Content.Close()
	retained, err := io.ReadAll(io.LimitReader(response.Content, MaxWorkerFamilyEvidenceBytes+1))
	if err != nil {
		return nil, err
	}
	if len(retained) > MaxWorkerFamilyEvidenceBytes {
		return nil, fmt.Errorf("%w: sequence evidence size", ErrInvalidReceipt)
	}
	previous, err := verifySequenceHead(retained, roots, head.Identity.Role, head.Identity.Environment)
	if err != nil {
		return nil, err
	}
	previousMigration, err := trust.Fingerprint(previous.Migration)
	if err != nil {
		return nil, err
	}
	if previousMigration != migration || previous.Sequence != head.Sequence || previous.Identity != head.Identity {
		return nil, ErrSequenceConflict
	}
	return retained, nil
}
