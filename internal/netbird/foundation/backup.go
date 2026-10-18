package foundation

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	"golang.org/x/sys/unix"
)

const backupPrefix = "netbird/foundation/v2/"
const maxBackupBytes int64 = 2 << 30

// ErrNoBackup distinguishes an empty protected bucket from refused access.
var ErrNoBackup = errors.New("no NetBird recovery archive exists")

// BackupTarget freezes both recovery destinations from the admitted foundation.
// Its current proofs are separate from the stable archive identity.
type BackupTarget struct {
	client       objectstorage.ObjectStorageClient
	scope        backupScope
	index        int
	manager      region.VerifiedNetBirdManager
	material     region.VerifiedBootstrapMaterial
	original     *region.VerifiedOriginalNetBirdBackupAuthority
	destinations [2]region.VerifiedBackupDestination
}

type backupDestination struct {
	Region        string `json:"region"`
	Bucket        string `json:"bucket"`
	BucketID      string `json:"bucket_id"`
	CompartmentID string `json:"compartment_id"`
	KMSKeyID      string `json:"kms_key_id"`
}

type backupScope struct {
	InstallationID  string               `json:"installation_id"`
	StoreGeneration string               `json:"store_generation"`
	TenancyID       string               `json:"tenancy_id"`
	Namespace       string               `json:"namespace"`
	Destinations    [2]backupDestination `json:"destinations"`
}

func (scope backupScope) validate() error {
	if !entityid.Valid(scope.InstallationID) || scope.StoreGeneration != entityid.Derive("netbird-foundation-store", scope.InstallationID)+":1" ||
		!strings.HasPrefix(scope.TenancyID, "ocid1.tenancy.oc1..") || scope.Namespace == "" {
		return errors.New("NetBird recovery requires an admitted installation, tenancy and stable store generation")
	}
	for i, destination := range scope.Destinations {
		if destination.Region != [2]string{"sa-saopaulo-1", "us-sanjose-1"}[i] || destination.Bucket == "" ||
			!strings.HasPrefix(destination.BucketID, "ocid1.bucket.oc1."+destination.Region+".") ||
			!strings.HasPrefix(destination.KMSKeyID, "ocid1.key.oc1."+destination.Region+".") ||
			!strings.HasPrefix(destination.CompartmentID, "ocid1.compartment.oc1..") {
			return errors.New("NetBird recovery requires the exact admitted GRU and SFO destination set")
		}
	}
	return nil
}

func (scope backupScope) prefix() (string, error) {
	if err := scope.validate(); err != nil {
		return "", err
	}
	wire, err := json.Marshal(scope, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(wire)
	return backupPrefix + hex.EncodeToString(digest[:]) + "/", nil
}

// NewBackupTargets derives recovery scope from real manager and foundation proofs.
// Renewed grants can reconstruct these proofs without changing archive identity.
func NewBackupTargets(ctx context.Context, factory *ociclient.Factory, resolver region.FoundationResolver, manager region.VerifiedNetBirdManager) ([2]BackupTarget, error) {
	var targets [2]BackupTarget
	if factory == nil || factory.Provider() == nil {
		return targets, errors.New("NetBird recovery requires an OCI identity provider")
	}
	authority, err := resolver.OriginalNetBirdBackup(ctx, manager)
	if err != nil && !errors.Is(err, region.ErrNotOriginalNetBirdManager) {
		return targets, err
	}
	var material region.VerifiedBootstrapMaterial
	var original *region.VerifiedOriginalNetBirdBackupAuthority
	var destinations [2]region.VerifiedBackupDestination
	var scope backupScope
	if err == nil {
		original = &authority
		tenancy, err := factory.Provider().TenancyOCID()
		if err != nil {
			return targets, err
		}
		if tenancy != authority.TenancyID() {
			return targets, errors.New("original NetBird recovery belongs to a different tenancy")
		}
		scope = backupScope{InstallationID: authority.InstallationID(), StoreGeneration: authority.StoreGeneration(), TenancyID: tenancy, Namespace: authority.Namespace()}
		destinations = authority.Destinations()
		for i, destination := range destinations {
			vault := destination.VaultTarget()
			scope.Destinations[i] = backupDestination{Region: destination.OCIRegion(), Bucket: destination.BucketName(), BucketID: destination.BucketID(), CompartmentID: vault.CompartmentID, KMSKeyID: vault.KeyID}
		}
	} else {
		material, err = resolver.BootstrapMaterial(ctx, "GRU")
		if err != nil {
			return targets, err
		}
		if err := material.Revalidate(ctx); err != nil {
			return targets, err
		}
		tenancy, err := factory.Provider().TenancyOCID()
		if err != nil {
			return targets, err
		}
		scope = backupScope{InstallationID: material.InstallationID(), StoreGeneration: manager.StoreGeneration(), TenancyID: tenancy, Namespace: material.StorageDomain().Namespace}
		for i, cell := range [2]string{"GRU", "SFO"} {
			record, err := resolver.Resolve(ctx, cell)
			if err != nil {
				return targets, err
			}
			destination, err := resolver.BackupDestination(ctx, cell)
			if err != nil {
				return targets, err
			}
			if err := destination.Check(ctx); err != nil {
				return targets, err
			}
			vault, err := record.VaultTarget()
			if err != nil {
				return targets, err
			}
			if record.TenancyID != tenancy || destination.VaultTarget() != vault || i == 0 && manager.VaultTarget() != vault {
				return targets, errors.New("NetBird recovery authority belongs to a different tenancy or manager foundation")
			}
			destinations[i] = destination
			scope.Destinations[i] = backupDestination{Region: destination.OCIRegion(), Bucket: destination.BucketName(), BucketID: destination.BucketID(), CompartmentID: vault.CompartmentID, KMSKeyID: vault.KeyID}
		}
	}
	if err := scope.validate(); err != nil {
		return targets, err
	}
	for i, destination := range scope.Destinations {
		regional, err := factory.ForRegion(destination.Region)
		if err != nil {
			return targets, err
		}
		client, err := regional.ObjectStorage()
		if err != nil {
			return targets, err
		}
		targets[i] = BackupTarget{client: client, scope: scope, index: i, manager: manager, material: material, original: original, destinations: destinations}
		if err := targets[i].protected(ctx); err != nil {
			return [2]BackupTarget{}, err
		}
	}
	return targets, nil
}

func (target BackupTarget) checkAuthority(ctx context.Context) error {
	if err := target.scope.validate(); err != nil {
		return err
	}
	if target.index < 0 || target.index >= len(target.scope.Destinations) {
		return errors.New("NetBird recovery destination is absent")
	}
	var installationID, namespace string
	if target.original != nil {
		if err := target.original.Check(ctx); err != nil {
			return err
		}
		installationID, namespace = target.original.InstallationID(), target.original.Namespace()
		if target.original.StoreGeneration() != target.scope.StoreGeneration || target.original.TenancyID() != target.scope.TenancyID {
			return errors.New("original NetBird recovery store or tenancy changed")
		}
	} else {
		if err := target.manager.Check(ctx); err != nil {
			return err
		}
		if err := target.material.Revalidate(ctx); err != nil {
			return err
		}
		installationID, namespace = target.material.InstallationID(), target.material.StorageDomain().Namespace
	}
	if target.manager.StoreGeneration() != target.scope.StoreGeneration || installationID != target.scope.InstallationID || namespace != target.scope.Namespace {
		return errors.New("NetBird recovery installation or store scope changed")
	}
	for i, destination := range target.destinations {
		if target.original == nil {
			if err := destination.Check(ctx); err != nil {
				return err
			}
		}
		vault := destination.VaultTarget()
		expected := backupDestination{Region: destination.OCIRegion(), Bucket: destination.BucketName(), BucketID: destination.BucketID(), CompartmentID: vault.CompartmentID, KMSKeyID: vault.KeyID}
		if expected != target.scope.Destinations[i] || i == 0 && vault != target.manager.VaultTarget() {
			return errors.New("NetBird recovery destination set changed")
		}
	}
	return ctx.Err()
}

func (target BackupTarget) requestContext(ctx context.Context) context.Context {
	return ociclient.WithRequestGuard(ctx, target.checkAuthority)
}

// BackupRecord contains no credentials. Object alone identifies a recoverable
// archive: its name includes the creation time and the SHA-256 of all its bytes.
type BackupRecord struct {
	Object    string    `json:"object"`
	CreatedAt time.Time `json:"created_at"`
	Bytes     int64     `json:"bytes"`
}

type backupManifest struct {
	Version   int         `json:"version"`
	CreatedAt time.Time   `json:"created_at"`
	Scope     backupScope `json:"scope"`
}

// Backup quiesces the sole server while copying its complete data directory and
// rendered config, then resumes it before uploading two verified off-host copies.
// quiesce must stop all writers and return a restart function; configPath must
// remain readable after stopping the service (systemd RuntimeDirectoryPreserve).
func Backup(ctx context.Context, dataDir, configPath string, targets [2]BackupTarget,
	quiesce func(context.Context) (func(context.Context) error, error),
) (record BackupRecord, err error) {
	if quiesce == nil || targets[0].index != 0 || targets[1].index != 1 || targets[0].scope != targets[1].scope {
		return record, errors.New("NetBird backup requires quiescence and admitted GRU and SFO targets")
	}
	for _, target := range targets {
		if err := target.protected(ctx); err != nil {
			return record, err
		}
	}
	lock, err := os.OpenFile(filepath.Join(filepath.Dir(dataDir), ".backup.lock"), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return record, err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return record, fmt.Errorf("another NetBird snapshot is active: %w", err)
	}
	archive, err := os.CreateTemp(filepath.Dir(dataDir), ".netbird-backup-*.tar")
	if err != nil {
		return record, err
	}
	defer func() { err = errors.Join(err, archive.Close(), os.Remove(archive.Name())) }()
	for _, target := range targets {
		if err := target.checkAuthority(ctx); err != nil {
			return record, err
		}
	}
	record, err = snapshotBackup(ctx, archive, dataDir, configPath, targets[0].scope, quiesce)
	if err != nil {
		return record, err
	}
	for _, target := range targets {
		if err := target.checkAuthority(ctx); err != nil {
			return record, err
		}
		if err := target.upload(target.requestContext(ctx), archive, record); err != nil {
			return record, err
		}
	}
	return record, nil
}

// snapshotBackup owns only the quiesced local archive, never manager admission.
func snapshotBackup(ctx context.Context, archive *os.File, dataDir, configPath string, scope backupScope,
	quiesce func(context.Context) (func(context.Context) error, error),
) (record BackupRecord, err error) {
	prefix, err := scope.prefix()
	if err != nil {
		return record, err
	}
	if quiesce == nil {
		return record, errors.New("NetBird snapshot requires quiescence")
	}
	resume, err := quiesce(ctx)
	if err != nil {
		return record, err
	}
	if resume == nil {
		return record, errors.New("NetBird quiesce returned no restart function")
	}
	record.CreatedAt = time.Now().UTC()
	snapshotErr := writeBackup(ctx, archive, dataDir, configPath, scope, record.CreatedAt)
	restartCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	restartErr := resume(restartCtx)
	cancel()
	if err := errors.Join(snapshotErr, restartErr); err != nil {
		return record, err
	}
	info, err := archive.Stat()
	if err != nil {
		return record, err
	}
	record.Bytes = info.Size()
	if record.Bytes > maxBackupBytes+(16<<20) {
		return record, errors.New("NetBird archive exceeds the recovery bound")
	}
	digest, err := backupDigest(archive, record.Bytes)
	if err != nil {
		return record, err
	}
	record.Object = prefix + record.CreatedAt.Format("20060102T150405.000000000Z") + "/" + hex.EncodeToString(digest[:]) + ".tar"
	return record, nil
}

func (target BackupTarget) upload(ctx context.Context, archive *os.File, record BackupRecord) error {
	if _, _, err := backupObjectDigest(target.scope, record.Object); err != nil {
		return err
	}
	if err := target.protectedBucket(ctx); err != nil {
		return err
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return err
	}
	digest, err := backupDigest(archive, record.Bytes)
	if err != nil {
		return err
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return err
	}
	destination := target.scope.Destinations[target.index]
	_, err = target.client.PutObject(ociclient.RequestContext(ctx), objectstorage.PutObjectRequest{
		NamespaceName: new(target.scope.Namespace), BucketName: new(destination.Bucket), ObjectName: new(record.Object),
		PutObjectBody: io.NopCloser(archive), ContentLength: new(record.Bytes), ContentType: new("application/x-tar"),
		IfNoneMatch: new("*"), OpcSseKmsKeyId: new(destination.KMSKeyID),
		OpcChecksumAlgorithm: objectstorage.PutObjectOpcChecksumAlgorithmSha256,
		OpcContentSha256:     new(base64.StdEncoding.EncodeToString(digest[:])),
	})
	if err != nil {
		return fmt.Errorf("upload NetBird backup in %s: %w", destination.Region, err)
	}
	if err := target.download(ctx, record.Object, io.Discard); err != nil {
		return fmt.Errorf("verify NetBird backup in %s: %w", destination.Region, err)
	}
	return nil
}

func (target BackupTarget) protected(ctx context.Context) error {
	if err := target.checkAuthority(ctx); err != nil {
		return err
	}
	return target.protectedBucket(target.requestContext(ctx))
}

func (target BackupTarget) protectedBucket(ctx context.Context) error {
	if err := target.scope.validate(); err != nil {
		return err
	}
	if target.index < 0 || target.index >= len(target.scope.Destinations) {
		return errors.New("NetBird recovery destination is absent")
	}
	destination := target.scope.Destinations[target.index]
	for _, name := range ociclient.SecretUnsafeEnv {
		if os.Getenv(name) != "" {
			return fmt.Errorf("NetBird recovery refuses unsafe OCI variable %s", name)
		}
	}
	bucket, err := target.client.GetBucket(ociclient.RequestContext(ctx), objectstorage.GetBucketRequest{NamespaceName: new(target.scope.Namespace), BucketName: new(destination.Bucket)})
	if err != nil {
		return fmt.Errorf("inspect NetBird recovery bucket in %s: %w", destination.Region, err)
	}
	if bucket.Id == nil || *bucket.Id != destination.BucketID || bucket.CompartmentId == nil || *bucket.CompartmentId != destination.CompartmentID ||
		bucket.Namespace == nil || *bucket.Namespace != target.scope.Namespace || bucket.Name == nil || *bucket.Name != destination.Bucket ||
		bucket.KmsKeyId == nil || *bucket.KmsKeyId != destination.KMSKeyID || bucket.PublicAccessType != objectstorage.BucketPublicAccessTypeNopublicaccess {
		return errors.New("NetBird recovery bucket identity, privacy or KMS protection changed")
	}
	rules, err := target.client.ListRetentionRules(ociclient.RequestContext(ctx), objectstorage.ListRetentionRulesRequest{NamespaceName: new(target.scope.Namespace), BucketName: new(destination.Bucket)})
	if err != nil {
		return err
	}
	for _, rule := range rules.Items {
		if rule.TimeRuleLocked == nil || rule.TimeRuleLocked.After(time.Now()) {
			continue
		}
		if rule.Duration == nil || rule.Duration.TimeAmount != nil &&
			(rule.Duration.TimeUnit == objectstorage.DurationTimeUnitDays && *rule.Duration.TimeAmount >= 7 ||
				rule.Duration.TimeUnit == objectstorage.DurationTimeUnitYears && *rule.Duration.TimeAmount >= 1) {
			return nil
		}
	}
	return errors.New("NetBird recovery bucket requires locked retention of at least seven days")
}

func writeBackup(ctx context.Context, destination io.Writer, dataDir, configPath string, scope backupScope, created time.Time) error {
	writer := tar.NewWriter(destination)
	manifest, err := json.Marshal(backupManifest{Version: 2, CreatedAt: created, Scope: scope})
	if err != nil {
		return err
	}
	if err := writer.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o600, Size: int64(len(manifest)), Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	if _, err := writer.Write(manifest); err != nil {
		return err
	}
	root, err := os.OpenRoot(dataDir)
	if err != nil {
		return err
	}
	defer root.Close()
	total, stores := int64(len(manifest)), 0
	err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return errors.New("NetBird data contains a symlink or non-regular file")
		}
		file, err := root.Open(name)
		if err != nil {
			return err
		}
		err = appendBackupFile(writer, "data/"+name, file, &total)
		err = errors.Join(err, file.Close())
		if strings.HasSuffix(name, ".db") {
			stores++
		}
		return err
	})
	if err != nil {
		return err
	}
	if stores == 0 {
		return errors.New("NetBird backup contains no SQLite store")
	}
	config, err := os.Open(configPath)
	if err != nil {
		return err
	}
	err = appendBackupFile(writer, "config.yaml", config, &total)
	return errors.Join(err, config.Close(), writer.Close())
}

func appendBackupFile(writer *tar.Writer, name string, file *os.File, total *int64) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	*total += info.Size()
	if !info.Mode().IsRegular() || *total > maxBackupBytes || name == "config.yaml" && info.Size() == 0 {
		return errors.New("NetBird backup file is invalid or exceeds the two GiB recovery bound")
	}
	if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: info.Size(), Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	_, err = io.CopyN(writer, file, info.Size())
	return err
}

func backupDigest(file *os.File, size int64) ([32]byte, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return [32]byte{}, err
	}
	hash := sha256.New()
	_, err := io.CopyN(hash, file, size)
	return [32]byte(hash.Sum(nil)), err
}

func backupObjectDigest(scope backupScope, object string) (time.Time, string, error) {
	prefix, err := scope.prefix()
	if err != nil {
		return time.Time{}, "", err
	}
	relative, ok := strings.CutPrefix(object, prefix)
	stamp, digest, found := strings.Cut(relative, "/")
	if !ok || !found {
		return time.Time{}, "", errors.New("NetBird recovery object belongs to a different store or destination scope")
	}
	created, err := time.Parse("20060102T150405.000000000Z", stamp)
	if err != nil {
		return time.Time{}, "", errors.New("invalid NetBird recovery timestamp")
	}
	digest, ok = strings.CutSuffix(digest, ".tar")
	wire, err := hex.DecodeString(digest)
	if !ok || err != nil || len(wire) != sha256.Size || hex.EncodeToString(wire) != digest {
		return time.Time{}, "", errors.New("invalid NetBird recovery digest")
	}
	return created, digest, nil
}

// LatestBackup discovers the newest immutable recovery object in an admitted
// region, so replacement hosts need no manually copied backup record.
func LatestBackup(ctx context.Context, target BackupTarget) (BackupRecord, error) {
	if err := target.checkAuthority(ctx); err != nil {
		return BackupRecord{}, err
	}
	return target.latestBackup(target.requestContext(ctx))
}

func (target BackupTarget) latestBackup(ctx context.Context) (BackupRecord, error) {
	var latest BackupRecord
	if err := target.protectedBucket(ctx); err != nil {
		return latest, err
	}
	prefix, err := target.scope.prefix()
	if err != nil {
		return latest, err
	}
	destination := target.scope.Destinations[target.index]
	request := objectstorage.ListObjectsRequest{
		NamespaceName: new(target.scope.Namespace), BucketName: new(destination.Bucket),
		Prefix: new(prefix), Fields: new("name,size"), Limit: new(1000),
	}
	for {
		response, err := target.client.ListObjects(ociclient.RequestContext(ctx), request)
		if err != nil {
			return latest, err
		}
		for _, object := range response.Objects {
			if object.Name == nil || object.Size == nil || *object.Size <= 0 || *object.Size > maxBackupBytes+(16<<20) {
				return latest, errors.New("NetBird recovery inventory has an invalid object")
			}
			created, _, err := backupObjectDigest(target.scope, *object.Name)
			if err != nil {
				return latest, err
			}
			if *object.Name > latest.Object {
				latest = BackupRecord{Object: *object.Name, CreatedAt: created, Bytes: *object.Size}
			}
		}
		if response.NextStartWith == nil || *response.NextStartWith == "" {
			break
		}
		if request.Start != nil && *response.NextStartWith <= *request.Start {
			return latest, errors.New("NetBird recovery inventory pagination did not advance")
		}
		request.Start = response.NextStartWith
	}
	if latest.Object == "" {
		return latest, ErrNoBackup
	}
	return latest, nil
}

func (target BackupTarget) download(ctx context.Context, object string, destination io.Writer) error {
	_, want, err := backupObjectDigest(target.scope, object)
	if err != nil {
		return err
	}
	response, err := target.client.GetObject(ociclient.RequestContext(ctx), objectstorage.GetObjectRequest{
		NamespaceName: new(target.scope.Namespace), BucketName: new(target.scope.Destinations[target.index].Bucket), ObjectName: new(object),
	})
	if err != nil {
		return err
	}
	if response.Content == nil {
		return errors.New("NetBird recovery returned no object body")
	}
	defer response.Content.Close()
	if response.ContentLength == nil || *response.ContentLength <= 0 || *response.ContentLength > maxBackupBytes+(16<<20) {
		return errors.New("NetBird recovery object has an invalid size")
	}
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(destination, hash), io.LimitReader(response.Content, *response.ContentLength+1))
	if err != nil || n != *response.ContentLength || hex.EncodeToString(hash.Sum(nil)) != want {
		return errors.Join(errors.New("NetBird recovery object failed size or SHA-256 verification"), err)
	}
	return nil
}

// Restore creates replacementDir atomically. It refuses any existing target,
// verifies bytes before extraction and never activates a second manager.
// The service owner must fence the old host before activating this identity.
func Restore(ctx context.Context, target BackupTarget, object, replacementDir string) (manifestTime time.Time, err error) {
	if err := target.checkAuthority(ctx); err != nil {
		return manifestTime, err
	}
	if _, _, err := backupObjectDigest(target.scope, object); err != nil {
		return manifestTime, err
	}
	if err := target.protected(ctx); err != nil {
		return manifestTime, err
	}
	archive, err := os.CreateTemp(filepath.Dir(replacementDir), ".netbird-restore-*.tar")
	if err != nil {
		return manifestTime, err
	}
	defer func() { err = errors.Join(err, archive.Close(), os.Remove(archive.Name())) }()
	if err := target.download(target.requestContext(ctx), object, archive); err != nil {
		return manifestTime, err
	}
	stage, created, err := extractBackup(ctx, archive, target.scope, object, replacementDir)
	if err != nil {
		return manifestTime, err
	}
	defer os.RemoveAll(stage)
	if err := target.checkAuthority(ctx); err != nil {
		return manifestTime, err
	}
	if err := publishBackup(stage, replacementDir); err != nil {
		return manifestTime, err
	}
	return created, nil
}

// extractBackup validates scope before creating any extracted store directory.
func extractBackup(ctx context.Context, archive *os.File, scope backupScope, object, replacementDir string) (stage string, manifestTime time.Time, err error) {
	created, _, err := backupObjectDigest(scope, object)
	if err != nil {
		return "", manifestTime, err
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return "", manifestTime, err
	}
	reader := tar.NewReader(archive)
	header, err := reader.Next()
	if err != nil || header.Name != "manifest.json" || header.Typeflag != tar.TypeReg || header.Size <= 0 || header.Size > 16384 {
		return "", manifestTime, errors.New("NetBird recovery manifest is missing or invalid")
	}
	wire, err := io.ReadAll(reader)
	if err != nil {
		return "", manifestTime, err
	}
	var manifest backupManifest
	if err := json.Unmarshal(wire, &manifest, json.RejectUnknownMembers(true)); err != nil || manifest.Version != 2 || manifest.CreatedAt.IsZero() || !manifest.CreatedAt.Equal(created) || manifest.Scope != scope {
		return "", manifestTime, errors.New("NetBird recovery manifest version, time or store/destination scope is invalid")
	}
	if _, err := os.Lstat(replacementDir); !errors.Is(err, fs.ErrNotExist) {
		return "", manifestTime, errors.New("NetBird restore requires an absent isolated replacement directory")
	}
	stage, err = os.MkdirTemp(filepath.Dir(replacementDir), ".netbird-restore-*")
	if err != nil {
		return "", manifestTime, err
	}
	cleanupStage := stage
	defer func() {
		if err != nil {
			_ = os.RemoveAll(cleanupStage)
		}
	}()
	root, err := os.OpenRoot(stage)
	if err != nil {
		return "", manifestTime, err
	}
	defer root.Close()
	total, stores, config := int64(0), 0, false
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", manifestTime, err
		}
		if err := ctx.Err(); err != nil {
			return "", manifestTime, err
		}
		total += header.Size
		if header.Typeflag != tar.TypeReg || header.Size < 0 || total > maxBackupBytes || !filepath.IsLocal(header.Name) || filepath.Clean(header.Name) != header.Name ||
			(header.Name != "config.yaml" && !strings.HasPrefix(header.Name, "data/")) {
			return "", manifestTime, errors.New("NetBird recovery contains an invalid file")
		}
		if err := root.MkdirAll(filepath.Dir(header.Name), 0o700); err != nil {
			return "", manifestTime, err
		}
		file, err := root.OpenFile(header.Name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return "", manifestTime, err
		}
		_, copyErr := io.CopyN(file, reader, header.Size)
		if err := errors.Join(copyErr, file.Sync(), file.Close()); err != nil {
			return "", manifestTime, err
		}
		config = config || header.Name == "config.yaml" && header.Size > 0
		if strings.HasSuffix(header.Name, ".db") && strings.HasPrefix(header.Name, "data/") {
			stores++
		}
	}
	if !config || stores == 0 {
		return "", manifestTime, errors.New("NetBird recovery lacks config or SQLite identity store")
	}
	return stage, manifest.CreatedAt, nil
}

func publishBackup(stage, replacementDir string) error {
	if err := unix.Renameat2(unix.AT_FDCWD, stage, unix.AT_FDCWD, replacementDir, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("install isolated NetBird recovery: %w", err)
	}
	return nil
}
