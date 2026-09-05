package candidatesync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/ociinstance"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarytransfer"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"terrascale.tech/orchestrator/src/orchestrator/restoredrill"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
)

type objectReader interface {
	ObserveBucket(context.Context) (provider.OCIBucketObservation, bool, error)
	HeadObject(context.Context, provider.ObjectRef) (provider.ObjectMetadata, bool, error)
	GetObject(context.Context, provider.ObjectRef) (io.ReadCloser, provider.ObjectMetadata, error)
}
type readerFactory func(context.Context, transitiongrant.CandidateSyncConfig, preliminarytransfer.Destination, string) (objectReader, func(), error)

func productionReader(ctx context.Context, c transitiongrant.CandidateSyncConfig, d preliminarytransfer.Destination, prefix string) (objectReader, func(), error) {
	identity, err := ociinstance.NewFromConfig(ctx, c.Identity, func(path string) ([]byte, error) { return initialgrant.ReadMaterialFile(path, 1<<20, true) })
	if err != nil {
		return nil, nil, err
	}
	closeIdentity := func() { identity.Close() }
	transport, err := identity.NewTransportForRegion(provider.OCIServiceObjectStorage, d.OCIRegion, max(c.MaxSnapshotBytes, preliminarytransfer.MaximumBytes))
	if err != nil {
		closeIdentity()
		return nil, nil, err
	}
	reader, err := provider.NewOCIObjectStorageReader(transport, provider.ObjectReadScope{Namespace: d.Namespace, Bucket: d.Bucket, Prefix: strings.TrimSuffix(prefix, "/") + "/", MaxObjectBytes: max(c.MaxSnapshotBytes, preliminarytransfer.MaximumBytes)})
	if err != nil {
		closeIdentity()
		return nil, nil, err
	}
	return reader, closeIdentity, nil
}

// Run is a finite admitted attempt. The caller holds the published-candidate
// mutation lock for its entire lifetime, including joined broker shutdown.
func Run(ctx context.Context, c transitiongrant.Config, v preliminarytransfer.VerifiedCandidate) ([]byte, error) {
	return run(ctx, c, v, productionReader)
}
func run(ctx context.Context, c transitiongrant.Config, v preliminarytransfer.VerifiedCandidate, factory readerFactory) (result []byte, err error) {
	if ctx == nil || factory == nil || c.Sync == nil {
		return nil, errors.New("candidatesync: context and admitted sync configuration required")
	}
	if err = c.Validate(); err != nil {
		return nil, err
	}
	if err = v.Check(time.Now()); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithDeadline(ctx, v.Authorization.ExpiresAt)
	defer cancel()
	check := func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		return v.Check(time.Now())
	}
	scope := v.Scope.Scope
	sync := *c.Sync
	var destination preliminarytransfer.Destination
	var candidate preliminarytransfer.Candidate
	for _, d := range scope.Destinations {
		if d.Region == c.Region {
			destination = d
		}
	}
	for _, a := range scope.Candidates {
		if a.NodeID == c.NodeID {
			candidate = a
		}
	}
	if c.TransitionID != scope.TransitionID || v.Authorization.NodeID != c.NodeID || candidate.Region != c.Region || candidate.ServerName != c.ServerName || candidate.ReceiptPublicKeyPEM != sync.ReceiptPublicKeyPEM || destination.OCIRegion != sync.Identity.Region || scope.MaxSnapshotBytes > sync.MaxSnapshotBytes || scope.MaxTotalBytes > sync.MaxTotalBytes || scope.MaxRestoreBytes > sync.MaxRestoreBytes {
		return nil, errors.New("candidatesync: configured candidate differs from owner scope")
	}
	objects := []preliminarytransfer.ObjectMapping{}
	var total int64
	for _, o := range scope.Objects {
		if o.Region != c.Region {
			continue
		}
		if o.Size < 1 || o.Size > scope.MaxSnapshotBytes || total > scope.MaxTotalBytes-o.Size {
			return nil, errors.New("candidatesync: admitted byte budgets exceeded")
		}
		total += o.Size
		objects = append(objects, o)
	}
	if len(objects) == 0 {
		return nil, errors.New("candidatesync: no exact candidate objects")
	}
	stage, err := newStage(sync.StagingDir, check)
	if err != nil {
		return nil, err
	}
	defer stage.close()
	scopePin, err := preliminarytransfer.CanonicalScope(scope)
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{".lock": true, "scope.json": true, "target": true, "publication.json": true}
	for _, o := range objects {
		allowed[artifactName(o)] = true
	}
	if err = pinStage(ctx, stage, scopePin, allowed); err != nil {
		return nil, err
	}
	receipts, err := newStage(sync.ReceiptDir, check)
	if err != nil {
		return nil, err
	}
	defer receipts.close()
	if err = pinStage(ctx, receipts, scopePin, map[string]bool{".lock": true, "scope.json": true, "receipt.json": true}); err != nil {
		return nil, err
	}
	// Reserve both broker budgets, all envelopes and one atomic envelope write.
	var stat unix.Statfs_t
	if err = unix.Fstatfs(int(stage.dir.Fd()), &stat); err != nil {
		return nil, err
	}
	needed := uint64(scope.MaxRestoreBytes)*2 + uint64(total) + uint64(scope.MaxSnapshotBytes) + (16 << 20)
	occupied, err := allocatedStageBytes(stage)
	if err != nil {
		return nil, err
	}
	if occupied < needed {
		needed -= occupied
	} else {
		needed = 0
	}
	if stat.Bsize <= 0 || stat.Bavail < needed/uint64(stat.Bsize)+1 {
		return nil, errors.New("candidatesync: physical staging reservation unavailable")
	}
	reader, closeReader, err := factory(ctx, sync, destination, scope.Prefix+"/")
	if err != nil {
		return nil, errors.New("candidatesync: instance identity or object reader unavailable")
	}
	defer closeReader()
	observation, found, err := reader.ObserveBucket(ctx)
	if err != nil || !found || observation.ID != destination.BucketResourceID || observation.CompartmentID != destination.CompartmentID || observation.Namespace != destination.Namespace || observation.Name != destination.Bucket || !reflect.DeepEqual(observation.FreeformTags, destination.OwnershipTags) {
		return nil, errors.New("candidatesync: exact bucket ownership observation differs")
	}
	publicationRef := provider.ObjectRef{Namespace: destination.Namespace, Bucket: destination.Bucket, Name: preliminarytransfer.PublicationKey(scope)}
	publicationHead, found, err := reader.HeadObject(ctx, publicationRef)
	if err != nil || !found || publicationHead.Size < 1 || publicationHead.Size > preliminarytransfer.MaximumBytes || publicationHead.ETag == "" {
		return nil, errors.New("candidatesync: publication HEAD unavailable")
	}
	publicationBody, publicationMeta, err := reader.GetObject(ctx, publicationRef)
	if err != nil || publicationBody == nil {
		return nil, errors.New("candidatesync: publication GET unavailable")
	}
	publicationRaw, err := io.ReadAll(io.LimitReader(publicationBody, preliminarytransfer.MaximumBytes+1))
	err = errors.Join(err, publicationBody.Close())
	if err != nil || publicationMeta != publicationHead || int64(len(publicationRaw)) != publicationHead.Size || !delivery.SameDigest(strings.TrimPrefix(delivery.SHA256Digest(publicationRaw), "sha256:"), publicationHead.SHA256) {
		return nil, errors.New("candidatesync: publication bytes differ")
	}
	publication, err := preliminarytransfer.CheckPublicationForScope(v.Scope, publicationRaw)
	if err != nil {
		return nil, err
	}
	if err = stage.publish(ctx, "publication.json", publicationRaw); err != nil {
		return nil, err
	}
	publicationETags := map[string]string{}
	for _, o := range publication.Objects {
		if o.Region == c.Region {
			publicationETags[o.ObjectKey] = o.ETag
		}
	}
	epoch, err := v.Scope.CaptureEpoch()
	if err != nil {
		return nil, err
	}
	capture, err := v.Scope.HistoricalCapture()
	if err != nil {
		return nil, err
	}
	for _, o := range objects {
		if err = check(); err != nil {
			return nil, err
		}
		ref := provider.ObjectRef{Namespace: destination.Namespace, Bucket: destination.Bucket, Name: o.ObjectKey}
		head, found, e := reader.HeadObject(ctx, ref)
		if e != nil || !found || !metadataMatches(head, o) || head.ETag != publicationETags[o.ObjectKey] {
			return nil, errors.New("candidatesync: exact object HEAD differs")
		}
		body, meta, e := reader.GetObject(ctx, ref)
		if e != nil || body == nil {
			return nil, errors.New("candidatesync: exact object GET unavailable")
		}
		raw, e := io.ReadAll(io.LimitReader(body, o.Size+1))
		e = errors.Join(e, body.Close())
		if e != nil || meta != head || int64(len(raw)) != o.Size || delivery.SHA256Digest(raw) != o.SHA256 {
			return nil, errors.New("candidatesync: downloaded object identity differs")
		}
		request, created, e := restoredrill.SnapshotEnvelopeRequest(raw, o.Stream, scope.MaxSnapshotBytes)
		if e != nil || request.ControlEpoch != epoch || request.ObjectKey != o.LocalKey || request.RunID != scope.TransitionID || request.IdempotencyKey != scope.TransitionID || created.Before(capture.Request.IssuedAt) || !created.Before(capture.Request.ExpiresAt) {
			return nil, errors.New("candidatesync: historical snapshot request differs")
		}
		if err = stage.publish(ctx, artifactName(o), raw); err != nil {
			return nil, err
		}
		reread, exists, e := stage.read(artifactName(o), o.Size)
		if e != nil || !exists || !bytes.Equal(raw, reread) {
			return nil, errors.New("candidatesync: durable downloaded readback differs")
		}
	}
	if err = check(); err != nil {
		return nil, err
	}
	targetPath := fmt.Sprintf("/proc/self/fd/%d/target", stage.dir.Fd())
	if err = ensureTarget(stage, targetPath, check); err != nil {
		return nil, err
	}
	referencePath, err := newReference(ctx, stage, scopePin)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(referencePath), stage.dir.Sync()) }()
	reference, err := startBroker(ctx, referencePath, scope.MaxRestoreBytes, objects)
	if err != nil {
		return nil, err
	}
	defer reference.close()
	target, err := startBroker(ctx, targetPath, scope.MaxRestoreBytes, objects)
	if err != nil {
		return nil, err
	}
	defer target.close()
	receipt := Receipt{Version: 1, PreliminaryOnly: true, ScopeSHA256: v.Scope.Digest, NodeID: c.NodeID, Region: c.Region, PreparationGrantSHA256: scope.PreparationGrantSHA256, BootstrapGrantSHA256: candidate.BootstrapGrantSHA256, ManifestSHA256: candidate.ManifestSHA256, SourceReceiptSHA256: scope.ReceiptSHA256, CaptureEpoch: epoch, CreatedAt: time.Now().UTC(), Objects: []ObjectEvidence{}}
	for _, o := range objects {
		if err = check(); err != nil {
			return nil, err
		}
		raw, found, e := stage.read(artifactName(o), o.Size)
		if e != nil || !found || delivery.SHA256Digest(raw) != o.SHA256 {
			return nil, errors.New("candidatesync: retained archive differs")
		}
		expected, e := restoredrill.RestorePreliminarySnapshot(ctx, reference.connections[o.Account], o.Stream, raw, scope.MaxSnapshotBytes)
		if e != nil {
			return nil, e
		}
		actual, e := restoredrill.RestorePreliminarySnapshot(ctx, target.connections[o.Account], o.Stream, raw, scope.MaxSnapshotBytes)
		if e != nil {
			return nil, e
		}
		if !restoredrill.SameSnapshotRestoreEvidence(expected, actual) {
			return nil, errors.New("candidatesync: persistent target restore differs from reference")
		}
		evidenceRaw, e := json.Marshal(actual)
		if e != nil {
			return nil, e
		}
		receipt.Objects = append(receipt.Objects, ObjectEvidence{o, preliminarytransfer.Digest(evidenceRaw)})
	}
	// No signature or completed receipt is possible while either broker runs.
	target.close()
	reference.close()
	if err = syncTree(targetPath); err != nil {
		return nil, err
	}
	if err = stage.dir.Sync(); err != nil {
		return nil, err
	}
	if err = check(); err != nil {
		return nil, err
	}
	existing, found, err := receipts.read("receipt.json", preliminarytransfer.MaximumBytes)
	if err != nil {
		return nil, err
	}
	if found {
		prior, e := VerifyScopedReceipt(v.Scope, c.Region, existing, time.Now())
		if e != nil {
			return nil, e
		}
		receipt.CreatedAt = prior.CreatedAt
		a, _ := json.Marshal(receipt)
		b, _ := json.Marshal(prior)
		if !bytes.Equal(a, b) {
			return nil, errors.New("candidatesync: completed receipt differs from current restore evidence")
		}
		if err = receipts.dir.Sync(); err != nil {
			return nil, err
		}
		return existing, check()
	}
	key, err := initialgrant.ReadMaterialFile(sync.ReceiptPrivateKeyFile, 1<<20, true)
	if err != nil {
		return nil, err
	}
	signer, err := security.ParseCommandSignatureSignerPEM(key)
	clear(key)
	if err != nil {
		return nil, err
	}
	defer signer.Close()
	expectedKey, err := preliminarytransfer.PublicKeyID([]byte(sync.ReceiptPublicKeyPEM))
	if err != nil || signer.PublicKeyID() != expectedKey {
		return nil, errors.New("candidatesync: candidate receipt key differs")
	}
	receipt.CreatedAt = time.Now().UTC()
	raw, err := signReceipt(signer, receipt)
	if err != nil {
		return nil, err
	}
	if err = receipts.publish(ctx, "receipt.json", raw); err != nil {
		return nil, err
	}
	reread, found, err := receipts.read("receipt.json", preliminarytransfer.MaximumBytes)
	if err != nil || !found || !bytes.Equal(raw, reread) {
		return nil, errors.New("candidatesync: completed receipt readback differs")
	}
	return raw, check()
}
func artifactName(o preliminarytransfer.ObjectMapping) string {
	return preliminarytransfer.Digest([]byte(o.Account+"/"+o.LocalKey)) + ".snapshot"
}
func metadataMatches(m provider.ObjectMetadata, o preliminarytransfer.ObjectMapping) bool {
	return m.ETag != "" && m.Size == o.Size && delivery.SameDigest(m.SHA256, strings.TrimPrefix(o.SHA256, "sha256:"))
}
func pinStage(ctx context.Context, s *stage, pin []byte, allowed map[string]bool) error {
	prior, found, err := s.read("scope.json", preliminarytransfer.MaximumBytes)
	if err != nil {
		return err
	}
	if found && !bytes.Equal(prior, pin) {
		return errors.New("candidatesync: immutable scope conflict")
	}
	entries, err := s.entries()
	if err != nil {
		return err
	}
	if !found {
		for _, entry := range entries {
			if entry.Name() != ".lock" && !temporaryName(entry.Name(), ".staging-") {
				return errors.New("candidatesync: unpinned staging state retained")
			}
		}
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".staging-") {
			if err := recoverTemporary(ctx, s, entry.Name()); err != nil {
				return err
			}
			continue
		}
		if found && allowed["target"] && strings.HasPrefix(entry.Name(), ".reference-") {
			if err := recoverReference(ctx, s, entry.Name(), pin); err != nil {
				return err
			}
			continue
		}
		if !allowed[entry.Name()] || (!found && entry.Name() != ".lock") {
			return errors.New("candidatesync: unknown or unpinned staging state")
		}
	}
	return s.publish(ctx, "scope.json", pin)
}
func ensureTarget(s *stage, path string, check func() error) error {
	if err := check(); err != nil {
		return err
	}
	if err := unix.Mkdirat(int(s.dir.Fd()), "target", 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	if err := s.dir.Sync(); err != nil {
		return err
	}
	return inspectTree(path, false)
}
func inspectTree(path string, sync bool) error {
	return filepath.WalkDir(path, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		var stat unix.Stat_t
		if e = unix.Lstat(p, &stat); e != nil {
			return e
		}
		if stat.Uid != uint32(os.Geteuid()) || stat.Mode&0022 != 0 || (stat.Mode&unix.S_IFMT != unix.S_IFDIR && stat.Mode&unix.S_IFMT != unix.S_IFREG) || (stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Nlink != 1) {
			return errors.New("candidatesync: unsafe persistent broker entry")
		}
		if sync {
			f, e := os.Open(p)
			if e != nil {
				return e
			}
			return errors.Join(f.Sync(), f.Close())
		}
		return nil
	})
}
func syncTree(path string) error { return inspectTree(path, true) }
