package delivery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/artifact"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const ArtifactBucket = "TS_ARTIFACTS"

// The NATS server reports stream store rejections through its generic 10077
// error. The description carries the underlying discard-new store reason.
const jsStreamStoreFailedErrorCode jetstream.ErrorCode = 10077

type signedAdmission struct {
	Record   ArtifactRecord `json:"record"`
	Envelope []byte         `json:"envelope"`
	Actor    string         `json:"actor"`
}

func artifactKey(digest string) string { return "sha256-" + digest }

func admissionKey(digest, cell, role, environment string) string {
	return entityid.Derive("artifact-admission", digest, cell, role, environment)
}

const admissionCASAttempts = 8

// artifactUploadTimeout bounds one artifact upload, including every chunk ack.
const artifactUploadTimeout = 15 * time.Minute

func ArtifactClaimSubject(cell string) string {
	return protocol.DeliveryArtifactAdmitSubject(cell)
}

// PrepareArtifact uploads content-addressed bytes and returns a signed claim.
// It does not grant admission; the controller must process the claim with
// AcceptArtifactClaim before the artifact can be deployed.
func (s *Service) PrepareArtifact(ctx context.Context, reader io.ReadSeeker, request ArtifactClaimRequest) (record ArtifactRecord, claim []byte, resultErr error) {
	if s == nil || reader == nil {
		return ArtifactRecord{}, nil, fmt.Errorf("%w: missing artifact reader", ErrInvalid)
	}
	if err := request.validate(); err != nil || request.Cell != s.config.Cell {
		return ArtifactRecord{}, nil, fmt.Errorf("%w: artifact target or source", ErrInvalid)
	}
	if s.config.ArtifactSigner == nil {
		return ArtifactRecord{}, nil, errors.New("artifact signer is not configured")
	}
	snapshot, size, digest, err := stageArtifact(ctx, reader)
	if err != nil {
		return ArtifactRecord{}, nil, err
	}
	defer func() {
		cleanupErr := discardStagedArtifact(snapshot)
		if cleanupErr != nil {
			if resultErr == nil {
				record = ArtifactRecord{}
				claim = nil
			}
			resultErr = errors.Join(resultErr, cleanupErr)
		}
	}()
	if size == 0 || size > MaxArtifactBytes {
		return ArtifactRecord{}, nil, fmt.Errorf("%w: artifact size must be 1..%d bytes", ErrInvalid, MaxArtifactBytes)
	}
	r := ArtifactRecord{SchemaVersion: SchemaVersion, Digest: digest, Source: request.Source, Cell: request.Cell, Role: request.Role, Environment: request.Environment, Size: size}
	r.ManifestDigest, err = r.calculatedManifestDigest()
	if err != nil {
		return ArtifactRecord{}, nil, err
	}
	if err := s.storeArtifact(ctx, snapshot, r); err != nil {
		return ArtifactRecord{}, nil, err
	}
	// Sign only after the bytes are stored: the claim's short validity must
	// cover its admission, not an upload over a slow operator link.
	envelope, err := s.config.ArtifactSigner.SignArtifact(ctx, r)
	if err != nil {
		return ArtifactRecord{}, nil, fmt.Errorf("sign artifact claim: %w", err)
	}
	return r, envelope, nil
}

// storeArtifact stores the staged bytes of r unless the store already holds
// them, and checks the stored object against r.
func (s *Service) storeArtifact(ctx context.Context, snapshot *os.File, r ArtifactRecord) error {
	exists, err := s.artifactExistsForUpload(ctx, r)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	if _, err := snapshot.Seek(0, io.SeekStart); err != nil {
		return err
	}
	// Without a deadline every chunk ack gets only the JetStream default
	// timeout, which a slow operator link such as a bastion forward misses.
	uploadCtx, cancel := context.WithTimeout(ctx, artifactUploadTimeout)
	defer cancel()
	if _, err := s.artifacts.Put(uploadCtx, jetstream.ObjectMeta{Name: artifactKey(r.Digest)}, contextReader{uploadCtx, snapshot}); err != nil {
		if isArtifactStoreFullError(err) {
			return fmt.Errorf("store artifact: %w: %w", ErrArtifactStoreFull, err)
		}
		return fmt.Errorf("store artifact: %w", err)
	}
	return s.verifyArtifact(ctx, r)
}

// AdmitClaim is the controller's in-process admission of an artifact that
// CI uploaded somewhere only the controller reads (the region's head
// bucket, TS-610) with its signed claim. The claim is verified at its
// issuance instant, as an archived admission is, so the caller bounds its
// age; the bytes must be exactly the claimed ones. It returns the record and
// the authorized actor.
func (s *Service) AdmitClaim(ctx context.Context, reader io.ReadSeeker, claim []byte) (_ ArtifactRecord, _ string, resultErr error) {
	r, actor, err := s.VerifyClaim(ctx, claim)
	if err != nil {
		return ArtifactRecord{}, "", err
	}
	snapshot, size, digest, err := stageArtifact(ctx, reader)
	if err != nil {
		return ArtifactRecord{}, "", err
	}
	defer func() { resultErr = errors.Join(resultErr, discardStagedArtifact(snapshot)) }()
	if size != r.Size || digest != r.Digest {
		return ArtifactRecord{}, "", fmt.Errorf("%w: the artifact bytes are not the claimed ones", ErrInvalid)
	}
	if err := s.storeArtifact(ctx, snapshot, r); err != nil {
		return ArtifactRecord{}, "", err
	}
	if err := s.touchArtifact(ctx, r.Digest); err != nil {
		return ArtifactRecord{}, "", err
	}
	if err := s.persistArtifactAdmission(ctx, r, claim, actor); err != nil {
		return ArtifactRecord{}, "", err
	}
	return r, actor, nil
}

// VerifyClaim checks a signed artifact claim at its issuance instant and
// authorizes its signer for the claimed role, environment and repository,
// without admitting anything. It returns the record and the actor.
func (s *Service) VerifyClaim(ctx context.Context, claim []byte) (ArtifactRecord, string, error) {
	if s == nil || s.config.ArtifactVerifier == nil || s.config.AuthorizeArtifact == nil || len(claim) == 0 || len(claim) > MaxArtifactClaimBytes {
		return ArtifactRecord{}, "", fmt.Errorf("%w: artifact admission configuration or signed claim", ErrInvalid)
	}
	r, actor, err := s.config.ArtifactVerifier.VerifyArchivedArtifact(ctx, claim)
	if err != nil || actor == "" || r.validate() != nil || r.Cell != s.config.Cell {
		return ArtifactRecord{}, "", fmt.Errorf("%w: artifact signature or cell", ErrInvalid)
	}
	if err := s.config.AuthorizeArtifact(ctx, actor, r); err != nil {
		return ArtifactRecord{}, "", err
	}
	return r, actor, nil
}

func (s *Service) artifactExistsForUpload(ctx context.Context, r ArtifactRecord) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	// The modern ObjectStore.GetInfo uses direct reads when object-store
	// streams allow them. Its follower read can miss a committed object, so use
	// the legacy SDK's standard MSG.GET lookup before deciding to replace it.
	options := s.js.Options()
	legacyOptions := make([]nats.JSOpt, 0, 2)
	if options.Domain != "" {
		legacyOptions = append(legacyOptions, nats.Domain(options.Domain))
	} else if options.APIPrefix != "" {
		legacyOptions = append(legacyOptions, nats.APIPrefix(options.APIPrefix))
	}
	if options.DefaultTimeout > 0 {
		legacyOptions = append(legacyOptions, nats.MaxWait(options.DefaultTimeout))
	}
	legacyJS, err := s.js.Conn().JetStream(legacyOptions...)
	if err != nil {
		return false, fmt.Errorf("bind artifact metadata reader: %w", err)
	}
	metadata, missing, err := retryArtifactMetadataRead(ctx, func(attemptCtx context.Context) (*nats.RawStreamMsg, bool, error) {
		return authoritativeArtifactMetadata(attemptCtx, legacyJS, r.Digest)
	})
	if err != nil {
		return false, err
	}
	if missing {
		return false, nil
	}
	var info jetstream.ObjectInfo
	if err := json.Unmarshal(metadata.Data, &info); err != nil {
		return false, fmt.Errorf("inspect authoritative artifact metadata: %w", nats.ErrBadObjectMeta)
	}
	if info.Deleted {
		return false, nil
	}
	readCtx, cancel := context.WithTimeout(ctx, artifactUploadTimeout)
	defer cancel()
	err = artifact.ReadVerifiedAuthoritative(readCtx, s.js, &info, ArtifactBucket, artifactKey(r.Digest),
		r.Digest, r.Size, MaxArtifactBytes, io.Discard)
	if errors.Is(err, jetstream.ErrObjectNotFound) {
		// Only a leader-proven missing chunk permits repair; a changed reference fences it.
		if err := artifact.DeleteIfUnchanged(readCtx, legacyJS, ArtifactBucket, metadata); err != nil {
			return false, err
		}
		return false, nil
	}
	return err == nil, err
}

// The legacy ObjectStore.GetInfo uses this leader MSG.GET but discards its
// context option, while ObjectStore setup does an unbounded StreamInfo. Use
// the SDK's context-aware raw read so repairs retain its exact CAS revision.
func authoritativeArtifactMetadata(ctx context.Context, js nats.JetStreamContext, digest string) (*nats.RawStreamMsg, bool, error) {
	key := artifactKey(digest)
	subject := "$O." + ArtifactBucket + ".M." + base64.URLEncoding.EncodeToString([]byte(key))
	message, err := js.GetLastMsg("OBJ_"+ArtifactBucket, subject, nats.Context(ctx))
	if errors.Is(err, nats.ErrMsgNotFound) {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("inspect authoritative artifact metadata: %w", err)
	}
	if message == nil {
		return nil, false, fmt.Errorf("%w: authoritative artifact metadata is empty", ErrInvalid)
	}
	return message, false, nil
}

// A leader change can briefly reject the authoritative MSG.GET lookup. Retry
// only that read; a missing object permits upload, while an unresolved read
// failure never permits a Put.
func retryArtifactMetadataRead(ctx context.Context, read func(context.Context) (*nats.RawStreamMsg, bool, error)) (*nats.RawStreamMsg, bool, error) {
	retryCtx, cancel := context.WithTimeout(ctx, intentPublishTimeout)
	defer cancel()

	backoff := intentPublishInitialBackoff
	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		if err := retryCtx.Err(); err != nil {
			if lastErr != nil {
				return nil, false, lastErr
			}
			return nil, false, err
		}

		attemptCtx, stop := context.WithTimeout(retryCtx, intentPublishAttemptTimeout)
		info, missing, err := read(attemptCtx)
		attemptExpired := errors.Is(attemptCtx.Err(), context.DeadlineExceeded)
		stop()
		if err == nil {
			if parentErr := ctx.Err(); parentErr != nil {
				return nil, false, parentErr
			}
			if attemptExpired {
				return nil, false, context.DeadlineExceeded
			}
			return info, missing, nil
		}
		lastErr = err
		if parentErr := ctx.Err(); parentErr != nil {
			return nil, false, parentErr
		}
		if retryCtx.Err() != nil || !retryableSubmitOperationReadError(err, attemptExpired) {
			return nil, false, err
		}

		timer := time.NewTimer(backoff)
		select {
		case <-timer.C:
		case <-retryCtx.Done():
			timer.Stop()
			if parentErr := ctx.Err(); parentErr != nil {
				return nil, false, parentErr
			}
			return nil, false, err
		}
		backoff = min(backoff*2, intentPublishMaxBackoff)
	}
}

func isArtifactStoreFullError(err error) bool {
	apiErr, ok := errors.AsType[*jetstream.APIError](err)
	return ok && apiErr.ErrorCode == jsStreamStoreFailedErrorCode && apiErr.Description == "maximum bytes exceeded"
}

func stageArtifact(ctx context.Context, reader io.ReadSeeker) (*os.File, int64, string, error) {
	if _, err := reader.Seek(0, io.SeekStart); err != nil {
		return nil, 0, "", fmt.Errorf("seek artifact source: %w", err)
	}

	// CreateTemp creates files with mode 0600, so staged artifact bytes are not
	// readable by unrelated local users while they are being uploaded.
	snapshot, err := os.CreateTemp("", "ts-orchestrator-artifact-")
	if err != nil {
		return nil, 0, "", fmt.Errorf("stage artifact: %w", err)
	}
	hash := sha256.New()
	size, err := io.Copy(io.MultiWriter(snapshot, hash), io.LimitReader(contextReader{ctx, reader}, MaxArtifactBytes+1))
	if err != nil {
		return nil, 0, "", errors.Join(fmt.Errorf("stage artifact: %w", err), discardStagedArtifact(snapshot))
	}
	if size == 0 || size > MaxArtifactBytes {
		return nil, 0, "", errors.Join(
			fmt.Errorf("%w: artifact size must be 1..%d bytes", ErrInvalid, MaxArtifactBytes),
			discardStagedArtifact(snapshot),
		)
	}
	return snapshot, size, hex.EncodeToString(hash.Sum(nil)), nil
}

func discardStagedArtifact(snapshot *os.File) error {
	if snapshot == nil {
		return nil
	}
	return errors.Join(snapshot.Close(), os.Remove(snapshot.Name()))
}

// AcceptArtifactClaim is the controller's admission boundary. Operator and CI
// clients may publish the signed claim but must not write the admission KV.
func (s *Service) AcceptArtifactClaim(ctx context.Context, envelope []byte) (ArtifactRecord, error) {
	if s == nil || s.config.ArtifactVerifier == nil || s.config.AuthorizeArtifact == nil || len(envelope) == 0 || len(envelope) > MaxArtifactClaimBytes {
		return ArtifactRecord{}, fmt.Errorf("%w: artifact admission configuration or signed claim", ErrInvalid)
	}
	r, actor, err := s.config.ArtifactVerifier.VerifyArtifact(ctx, envelope)
	if err != nil || actor == "" || r.validate() != nil || r.Cell != s.config.Cell {
		return ArtifactRecord{}, fmt.Errorf("%w: artifact signature or cell", ErrInvalid)
	}
	if err := s.config.AuthorizeArtifact(ctx, actor, r); err != nil {
		return ArtifactRecord{}, err
	}
	// A collector that chose the object before this admission can no
	// longer delete it.
	if err := s.touchArtifact(ctx, r.Digest); err != nil {
		return ArtifactRecord{}, err
	}
	if err := s.verifyArtifact(ctx, r); err != nil {
		return ArtifactRecord{}, err
	}
	if err := s.persistArtifactAdmission(ctx, r, envelope, actor); err != nil {
		return ArtifactRecord{}, err
	}
	return r, nil
}

// touchArtifact pins a stored object for a new reference; see
// artifact.Touch.
func (s *Service) touchArtifact(ctx context.Context, digest string) error {
	if s.config.Conn == nil {
		return errors.New("artifact admission requires the controller's NATS connection")
	}
	js, err := s.config.Conn.JetStream()
	if err != nil {
		return err
	}
	err = artifact.Touch(ctx, js, ArtifactBucket, artifactKey(digest))
	if errors.Is(err, jetstream.ErrObjectNotFound) {
		return fmt.Errorf("%w: artifact object is not stored", ErrInvalid)
	}
	return err
}

// RetainArtifact validates the admitted bytes and touches their metadata before
// a caller commits a durable reference, fencing a concurrent GC deletion.
func (s *Service) RetainArtifact(ctx context.Context, record ArtifactRecord) error {
	resolved, err := s.ResolveAdmittedArtifact(ctx, record.Digest, record.Role, record.Environment)
	if err != nil {
		return err
	}
	if resolved != record {
		return ErrConflict
	}
	return s.touchArtifact(ctx, record.Digest)
}

func (s *Service) persistArtifactAdmission(ctx context.Context, record ArtifactRecord, envelope []byte, actor string) error {
	key := admissionKey(record.Digest, record.Cell, record.Role, record.Environment)
	newAdmission := signedAdmission{Record: record, Envelope: bytes.Clone(envelope), Actor: actor}
	encoded, err := json.Marshal(newAdmission)
	if err != nil {
		return err
	}
	for range admissionCASAttempts {
		entry, getErr := s.getAdmission(ctx, key)
		if errors.Is(getErr, jetstream.ErrKeyNotFound) {
			if _, createErr := s.admissions.Create(ctx, key, encoded); createErr == nil {
				return s.verifyCurrentAdmission(ctx, record)
			} else if errors.Is(createErr, jetstream.ErrKeyExists) {
				continue
			} else {
				return fmt.Errorf("admit artifact: %w", createErr)
			}
		}
		if getErr != nil {
			return getErr
		}
		oldAdmission, err := decodeStoredAdmission(entry.Value(), record.Digest, record.Cell, record.Role, record.Environment)
		if err != nil {
			return err
		}
		if oldAdmission.Record != record {
			return ErrConflict
		}
		if oldAdmission.Actor == actor && bytes.Equal(oldAdmission.Envelope, envelope) {
			return s.verifyCurrentAdmission(ctx, record)
		}
		if current, currentErr := s.readAdmission(ctx, record.Digest, record.Cell, record.Role, record.Environment); currentErr == nil {
			if current != record {
				return ErrConflict
			}
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.config.AuthorizeArtifact(ctx, actor, record); err != nil {
			return err
		}
		if err := s.verifyArtifact(ctx, record); err != nil {
			return err
		}
		updated := signedAdmission{Record: oldAdmission.Record, Envelope: bytes.Clone(envelope), Actor: actor}
		updateBytes, err := json.Marshal(updated)
		if err != nil {
			return err
		}
		if _, err := s.admissions.Update(ctx, key, updateBytes, entry.Revision()); err != nil {
			if errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
				continue
			}
			return fmt.Errorf("replace artifact admission: %w", err)
		}
		return s.verifyCurrentAdmission(ctx, record)
	}
	if current, err := s.readAdmission(ctx, record.Digest, record.Cell, record.Role, record.Environment); err == nil && current == record {
		return nil
	}
	return ErrConflict
}

func (s *Service) verifyCurrentAdmission(ctx context.Context, expected ArtifactRecord) error {
	current, err := s.readAdmission(ctx, expected.Digest, expected.Cell, expected.Role, expected.Environment)
	if err != nil {
		return err
	}
	if current != expected {
		return ErrConflict
	}
	return nil
}

func decodeStoredAdmission(value []byte, digest, cell, role, environment string) (signedAdmission, error) {
	var signed signedAdmission
	if err := protocol.DecodeStrict(value, &signed, MaxArtifactClaimBytes+4096); err != nil {
		return signedAdmission{}, fmt.Errorf("decode artifact admission: %w", err)
	}
	r := signed.Record
	if err := r.validate(); err != nil || r.Digest != digest || r.Cell != cell || r.Role != role || r.Environment != environment ||
		signed.Actor == "" || len(signed.Envelope) == 0 || len(signed.Envelope) > MaxArtifactClaimBytes {
		return signedAdmission{}, fmt.Errorf("invalid durable artifact admission: %w", ErrInvalid)
	}
	return signed, nil
}

// Admission decisions and CAS revisions must come from the stream leader.
// KeyValue.Get may read a follower whose direct-get view is stale.
func (s *Service) getAdmission(ctx context.Context, key string) (*operationValue, error) {
	if s == nil || s.config.Conn == nil {
		return nil, errors.New("delivery admission leader read requires NATS connection")
	}
	js, err := s.config.Conn.JetStream()
	if err != nil {
		return nil, err
	}
	subject := "$KV." + AdmissionBucket + "." + key
	msg, err := js.GetLastMsg("KV_"+AdmissionBucket, subject, nats.Context(ctx))
	if errors.Is(err, nats.ErrMsgNotFound) {
		return nil, jetstream.ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	return operationValueFromMsg(subject, msg)
}

func (s *Service) readAdmission(ctx context.Context, digest, cell, role, environment string) (ArtifactRecord, error) {
	e, err := s.getAdmission(ctx, admissionKey(digest, cell, role, environment))
	if err != nil {
		return ArtifactRecord{}, err
	}
	signed, err := decodeStoredAdmission(e.Value(), digest, cell, role, environment)
	if err != nil {
		return ArtifactRecord{}, err
	}
	r := signed.Record
	if s.config.ArtifactVerifier == nil {
		return ArtifactRecord{}, errors.New("artifact verifier is not configured")
	}
	verified, actor, err := s.config.ArtifactVerifier.VerifyArchivedArtifact(ctx, signed.Envelope)
	if err != nil || actor == "" || actor != signed.Actor || verified != r {
		return ArtifactRecord{}, fmt.Errorf("%w: durable artifact claim signature", ErrInvalid)
	}
	if s.config.AuthorizeArtifact == nil {
		return ArtifactRecord{}, errors.New("artifact authorizer is not configured")
	}
	if err := s.config.AuthorizeArtifact(ctx, actor, r); err != nil {
		return ArtifactRecord{}, err
	}
	return r, nil
}

// ResolveAdmittedArtifact returns an artifact only when its durable admission is
// valid under current signer authorization and its stored bytes match the digest.
func (s *Service) ResolveAdmittedArtifact(ctx context.Context, digest, role, environment string) (ArtifactRecord, error) {
	if s == nil || !sha256RE.MatchString(digest) || !nameRE.MatchString(role) || !nameRE.MatchString(environment) || !nameRE.MatchString(s.config.Cell) {
		return ArtifactRecord{}, fmt.Errorf("%w: artifact admission lookup", ErrInvalid)
	}
	record, err := s.readAdmission(ctx, digest, s.config.Cell, role, environment)
	if err != nil {
		return ArtifactRecord{}, err
	}
	if err := s.verifyArtifact(ctx, record); err != nil {
		return ArtifactRecord{}, err
	}
	return record, nil
}

// HistoricalArtifactClaim reads public provenance from an exact protected record.
// Callers must independently verify the envelope's historical signature and scope.
// It grants no current authority and does not prove original actor admission,
// execution, or existence before root retirement.
func (s *Service) HistoricalArtifactClaim(ctx context.Context, digest, role, environment string) (ArtifactRecord, []byte, error) {
	if s == nil || !sha256RE.MatchString(digest) || !nameRE.MatchString(role) || !nameRE.MatchString(environment) || !nameRE.MatchString(s.config.Cell) {
		return ArtifactRecord{}, nil, fmt.Errorf("%w: historical artifact lookup", ErrInvalid)
	}
	entry, err := s.getAdmission(ctx, admissionKey(digest, s.config.Cell, role, environment))
	if err != nil {
		return ArtifactRecord{}, nil, err
	}
	signed, err := decodeStoredAdmission(entry.Value(), digest, s.config.Cell, role, environment)
	if err != nil {
		return ArtifactRecord{}, nil, err
	}
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(signed.Envelope, &envelope, MaxArtifactClaimBytes); err != nil || envelope.Actor != signed.Actor {
		return ArtifactRecord{}, nil, fmt.Errorf("%w: historical artifact actor or envelope", ErrInvalid)
	}
	return signed.Record, bytes.Clone(signed.Envelope), nil
}

// RetainedArtifactClaim returns the original public signed claim after archived
// verification; migration consumers retain its exact issuance watermark.
func (s *Service) RetainedArtifactClaim(ctx context.Context, digest, role, environment string) ([]byte, error) {
	record, err := s.ResolveAdmittedArtifact(ctx, digest, role, environment)
	if err != nil {
		return nil, err
	}
	entry, err := s.getAdmission(ctx, admissionKey(digest, s.config.Cell, role, environment))
	if err != nil {
		return nil, err
	}
	signed, err := decodeStoredAdmission(entry.Value(), digest, s.config.Cell, role, environment)
	if err != nil {
		return nil, err
	}
	verified, actor, err := s.config.ArtifactVerifier.VerifyArchivedArtifact(ctx, signed.Envelope)
	if err != nil || verified != record || actor == "" || actor != signed.Actor {
		return nil, ErrUnauthorized
	}
	if err := s.config.AuthorizeArtifact(ctx, actor, record); err != nil {
		return nil, err
	}
	return bytes.Clone(signed.Envelope), nil
}

func (s *Service) verifyArtifact(ctx context.Context, r ArtifactRecord) error {
	delay := 20 * time.Millisecond
	for attempt := range artifactVisibilityAttempts {
		exists, err := s.checkArtifact(ctx, r)
		if err == nil && exists {
			return nil
		}
		if !(err == nil && !exists || errors.Is(err, jetstream.ErrObjectNotFound)) {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if attempt == artifactVisibilityAttempts-1 {
			return fmt.Errorf("%w: artifact object did not become visible", ErrInvalid)
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		delay = min(delay*2, maxArtifactVisibilityDelay)
	}
	return fmt.Errorf("%w: artifact object did not become visible", ErrInvalid)
}

const (
	artifactVisibilityAttempts = 8
	maxArtifactVisibilityDelay = 250 * time.Millisecond
)

func (s *Service) checkArtifact(ctx context.Context, r ArtifactRecord) (bool, error) {
	if r.Size <= 0 || r.Size > MaxArtifactBytes {
		return false, fmt.Errorf("%w: artifact size is outside bounds", ErrInvalid)
	}
	err := artifact.ReadVerified(ctx, s.js, s.artifacts, ArtifactBucket, artifactKey(r.Digest),
		r.Digest, r.Size, MaxArtifactBytes, io.Discard)
	if errors.Is(err, jetstream.ErrObjectNotFound) {
		return false, nil
	}
	if err != nil {
		if errors.Is(err, artifact.ErrInvalid) {
			return false, fmt.Errorf("%w: %w", ErrInvalid, err)
		}
		return false, err
	}
	return true, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func (s *Service) Artifacts() jetstream.ObjectStore { return s.artifacts }
