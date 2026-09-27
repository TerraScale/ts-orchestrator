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

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/artifact"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
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
	scope := sha256.Sum256([]byte(cell + "\x00" + role + "\x00" + environment))
	return "a_" + digest + "_" + hex.EncodeToString(scope[:])
}

const admissionCASAttempts = 8

func ArtifactClaimSubject(cell string) string {
	return "ts.orch.v1." + cell + ".delivery.artifact.admit"
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
	envelope, err := s.config.ArtifactSigner.SignArtifact(ctx, r)
	if err != nil {
		return ArtifactRecord{}, nil, fmt.Errorf("sign artifact claim: %w", err)
	}
	exists, err := s.artifactExistsForUpload(ctx, r.Digest)
	if err != nil {
		return ArtifactRecord{}, nil, err
	}
	if !exists {
		if _, err := snapshot.Seek(0, io.SeekStart); err != nil {
			return ArtifactRecord{}, nil, err
		}
		if _, err := s.artifacts.Put(ctx, jetstream.ObjectMeta{Name: artifactKey(r.Digest)}, contextReader{ctx, snapshot}); err != nil {
			if isArtifactStoreFullError(err) {
				return ArtifactRecord{}, nil, fmt.Errorf("store artifact: %w: %w", ErrArtifactStoreFull, err)
			}
			return ArtifactRecord{}, nil, fmt.Errorf("store artifact: %w", err)
		}
	}
	if err := s.verifyArtifact(ctx, r); err != nil {
		return ArtifactRecord{}, nil, err
	}
	return r, envelope, nil
}

func (s *Service) artifactExistsForUpload(ctx context.Context, digest string) (bool, error) {
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
	info, missing, err := retryArtifactMetadataRead(ctx, func(attemptCtx context.Context) (*nats.ObjectInfo, bool, error) {
		return authoritativeArtifactInfo(attemptCtx, legacyJS, digest)
	})
	if err != nil {
		return false, err
	}
	if missing {
		return false, nil
	}
	if info == nil {
		return false, fmt.Errorf("%w: authoritative artifact metadata is empty", ErrInvalid)
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return true, nil
}

// The legacy ObjectStore.GetInfo uses this leader MSG.GET but discards its
// context option, while ObjectStore setup does an unbounded StreamInfo. Use
// the SDK's context-aware raw read and decode the same metadata format.
func authoritativeArtifactInfo(ctx context.Context, js nats.JetStreamContext, digest string) (*nats.ObjectInfo, bool, error) {
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
	var info nats.ObjectInfo
	if err := json.Unmarshal(message.Data, &info); err != nil {
		return nil, false, fmt.Errorf("inspect authoritative artifact metadata: %w", nats.ErrBadObjectMeta)
	}
	if info.Deleted {
		return nil, true, nil
	}
	info.ModTime = message.Time
	return &info, false, nil
}

// A leader change can briefly reject the authoritative MSG.GET lookup. Retry
// only that read; a missing object permits upload, while an unresolved read
// failure never permits a Put.
func retryArtifactMetadataRead(ctx context.Context, read func(context.Context) (*nats.ObjectInfo, bool, error)) (*nats.ObjectInfo, bool, error) {
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
	if err := s.verifyArtifact(ctx, r); err != nil {
		return ArtifactRecord{}, err
	}
	if err := s.persistArtifactAdmission(ctx, r, envelope, actor); err != nil {
		return ArtifactRecord{}, err
	}
	return r, nil
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
