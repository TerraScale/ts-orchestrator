package release

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"io"
	"math"
	"net/http"
	"time"

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
	if err := identity.validate(); err != nil {
		return 0, err
	}
	for range 32 {
		head, etag, found, err := location.read(ctx, identity.Role, identity.Environment, roots)
		if err != nil {
			return 0, err
		}
		if !found {
			return 0, ErrSequenceMigrationRequired
		}
		migration, err := VerifySequenceMigrationHistorical(head.Migration, roots, identity.Role, identity.Environment)
		if err != nil {
			return 0, err
		}
		if len(signer) != ed25519.PrivateKeySize {
			return 0, trust.ErrKeyMismatch
		}
		signerID, err := trust.KeyID(signer.Public().(ed25519.PublicKey))
		if err != nil || signerID != migration.SignerKeyID {
			return 0, trust.ErrKeyMismatch
		}
		if head.Identity == identity {
			return head.Sequence, nil
		}
		if head.Sequence == math.MaxUint64 {
			return 0, fmt.Errorf("%w: sequence exhausted", ErrInvalidReceipt)
		}
		head.Sequence++
		head.Identity = identity
		payload, err := trust.EncodePayload(sequenceReservation{Sequence: head.Sequence, Identity: identity})
		if err != nil {
			return 0, err
		}
		now := time.Now().UTC()
		head.Reservation, err = trust.Sign(payload, sequenceReservationScope(identity.Role, identity.Environment), now, now.Add(MaxReceiptLifetime), signer)
		if err != nil {
			return 0, err
		}
		if err := location.write(ctx, identity.Role, identity.Environment, head, etag); errors.Is(err, ErrSequenceConflict) {
			continue
		} else if err != nil {
			return 0, err
		}
		return head.Sequence, nil
	}
	return 0, ErrSequenceConflict
}

// ImportMigration creates the ordering namespace once. A different migration
// never overwrites an allocated sequence or an earlier migration.
func (location SequenceLocation) ImportMigration(ctx context.Context, envelope trust.Envelope, roots trust.Keyring, role, environment string, now time.Time) error {
	migration, err := VerifySequenceMigrationHistorical(envelope, roots, role, environment)
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
	if _, err := VerifySequenceMigrationCurrent(envelope, roots, role, environment, now); err != nil {
		return err
	}
	err = location.write(ctx, role, environment, sequenceHead{Schema: "terrascale.release.sequence.v1", Sequence: migration.SequenceFloor, Migration: envelope}, etag)
	if !errors.Is(err, ErrSequenceConflict) {
		return err
	}
	// Another producer may initialize the exact same grant concurrently.
	head, _, found, err = location.read(ctx, role, environment, roots)
	if err != nil {
		return err
	}
	if found {
		retained, _ := trust.Fingerprint(head.Migration)
		incoming, _ := trust.Fingerprint(envelope)
		if retained == incoming {
			return nil
		}
	}
	return ErrSequenceConflict
}

func (location SequenceLocation) read(ctx context.Context, role, environment string, roots trust.Keyring) (sequenceHead, string, bool, error) {
	var head sequenceHead
	if location.Client == nil || location.Namespace == "" || location.Bucket == "" {
		return head, "", false, fmt.Errorf("%w: sequence location", ErrInvalidReceipt)
	}
	name := SequenceObject(role, environment)
	response, err := ociclient.ReadObject(ctx, location.Client, objectstorage.GetObjectRequest{NamespaceName: &location.Namespace, BucketName: &location.Bucket, ObjectName: &name})
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
	if err := protocol.DecodeStrict(wire, &head, trust.MaxEnvelopeBytes); err != nil {
		return head, "", false, err
	}
	migration, err := VerifySequenceMigrationHistorical(head.Migration, roots, role, environment)
	if err != nil {
		return head, "", false, err
	}
	if migration.Namespace != location.Namespace || migration.Bucket != location.Bucket {
		return head, "", false, fmt.Errorf("%w: migration sequence location", ErrInvalidReceipt)
	}
	if head.Schema != "terrascale.release.sequence.v1" || head.Sequence < migration.SequenceFloor || response.ETag == nil || *response.ETag == "" {
		return head, "", false, fmt.Errorf("%w: sequence head", ErrInvalidReceipt)
	}
	if head.Identity != (SequenceIdentity{}) {
		if err := head.Identity.validate(); err != nil {
			return head, "", false, err
		}
		if head.Identity.Role != role || head.Identity.Environment != environment || head.Sequence == migration.SequenceFloor {
			return head, "", false, fmt.Errorf("%w: sequence identity scope", ErrInvalidReceipt)
		}
	} else if head.Sequence != migration.SequenceFloor {
		return head, "", false, fmt.Errorf("%w: missing sequence identity", ErrInvalidReceipt)
	}
	if head.Identity != (SequenceIdentity{}) {
		public, _ := base64.RawURLEncoding.Strict().DecodeString(migration.SignerPublicKey)
		payload, err := trust.VerifyHistorical(head.Reservation, sequenceReservationScope(role, environment), trust.Keyring{migration.SignerKeyID: ed25519.PublicKey(public)}, trust.Policy{MaxLifetime: MaxReceiptLifetime})
		if err != nil {
			return head, "", false, err
		}
		reservation, err := decodeCanonicalPayload[sequenceReservation](payload)
		if err != nil {
			return head, "", false, err
		}
		if reservation.Sequence != head.Sequence || reservation.Identity != head.Identity {
			return head, "", false, fmt.Errorf("%w: unauthenticated sequence head", ErrInvalidReceipt)
		}
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
