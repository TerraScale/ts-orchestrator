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

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	"golang.org/x/sys/unix"
)

const backupPrefix = "netbird/foundation/v1/"
const maxBackupBytes int64 = 2 << 30

// ErrNoBackup distinguishes an empty protected bucket from refused access.
var ErrNoBackup = errors.New("no NetBird recovery archive exists")

// BackupTarget comes from the admitted OCI foundation inventory, never operator
// tuning. The caller obtains Client from the shared ociclient factory.
type BackupTarget struct {
	Client        objectstorage.ObjectStorageClient
	Region        string
	Namespace     string
	Bucket        string
	BucketID      string
	CompartmentID string
	KMSKeyID      string
}

// BackupRecord contains no credentials. Object alone identifies a recoverable
// archive: its name includes the creation time and the SHA-256 of all its bytes.
type BackupRecord struct {
	Object    string    `json:"object"`
	CreatedAt time.Time `json:"created_at"`
	Bytes     int64     `json:"bytes"`
}

type backupManifest struct {
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
}

// Backup quiesces the sole server while copying its complete data directory and
// rendered config, then resumes it before uploading two verified off-host copies.
// quiesce must stop all writers and return a restart function; configPath must
// remain readable after stopping the service (systemd RuntimeDirectoryPreserve).
func Backup(ctx context.Context, dataDir, configPath string, targets [2]BackupTarget,
	quiesce func(context.Context) (func(context.Context) error, error),
) (record BackupRecord, err error) {
	if quiesce == nil || targets[0].Region != "sa-saopaulo-1" || targets[1].Region != "us-sanjose-1" {
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
	resume, err := quiesce(ctx)
	if err != nil {
		return record, err
	}
	if resume == nil {
		return record, errors.New("NetBird quiesce returned no restart function")
	}
	record.CreatedAt = time.Now().UTC()
	snapshotErr := writeBackup(ctx, archive, dataDir, configPath, record.CreatedAt)
	// Cancellation must not leave the foundation offline after a failed backup.
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
	record.Object = backupPrefix + record.CreatedAt.Format("20060102T150405.000000000Z") + "/" + hex.EncodeToString(digest[:]) + ".tar"
	for _, target := range targets {
		if err := target.protected(ctx); err != nil {
			return record, err
		}
		if _, err := archive.Seek(0, io.SeekStart); err != nil {
			return record, err
		}
		_, err := target.Client.PutObject(ctx, objectstorage.PutObjectRequest{
			NamespaceName: new(target.Namespace), BucketName: new(target.Bucket), ObjectName: new(record.Object),
			PutObjectBody: io.NopCloser(archive), ContentLength: new(record.Bytes), ContentType: new("application/x-tar"),
			IfNoneMatch: new("*"), OpcSseKmsKeyId: new(target.KMSKeyID),
			OpcChecksumAlgorithm: objectstorage.PutObjectOpcChecksumAlgorithmSha256,
			OpcContentSha256:     new(base64.StdEncoding.EncodeToString(digest[:])),
		})
		if err != nil {
			return record, fmt.Errorf("upload NetBird backup in %s: %w", target.Region, err)
		}
		if err := target.download(ctx, record.Object, io.Discard); err != nil {
			return record, fmt.Errorf("verify NetBird backup in %s: %w", target.Region, err)
		}
	}
	return record, nil
}

func (target BackupTarget) protected(ctx context.Context) error {
	for _, name := range ociclient.SecretUnsafeEnv {
		if os.Getenv(name) != "" {
			return fmt.Errorf("NetBird recovery refuses unsafe OCI variable %s", name)
		}
	}
	if target.Namespace == "" || target.Bucket == "" || target.BucketID == "" || target.CompartmentID == "" || target.KMSKeyID == "" ||
		(target.Region != "sa-saopaulo-1" && target.Region != "us-sanjose-1") ||
		!strings.HasPrefix(target.BucketID, "ocid1.bucket.oc1."+target.Region+".") ||
		!strings.HasPrefix(target.KMSKeyID, "ocid1.key.oc1."+target.Region+".") ||
		!strings.HasPrefix(target.CompartmentID, "ocid1.compartment.oc1..") {
		return errors.New("NetBird recovery requires admitted bucket, compartment and regional KMS identities")
	}
	bucket, err := target.Client.GetBucket(ctx, objectstorage.GetBucketRequest{NamespaceName: new(target.Namespace), BucketName: new(target.Bucket)})
	if err != nil {
		return fmt.Errorf("inspect NetBird recovery bucket in %s: %w", target.Region, err)
	}
	if bucket.Id == nil || *bucket.Id != target.BucketID || bucket.CompartmentId == nil || *bucket.CompartmentId != target.CompartmentID ||
		bucket.Namespace == nil || *bucket.Namespace != target.Namespace || bucket.Name == nil || *bucket.Name != target.Bucket ||
		bucket.KmsKeyId == nil || *bucket.KmsKeyId != target.KMSKeyID || bucket.PublicAccessType != objectstorage.BucketPublicAccessTypeNopublicaccess {
		return errors.New("NetBird recovery bucket identity, privacy or KMS protection changed")
	}
	rules, err := target.Client.ListRetentionRules(ctx, objectstorage.ListRetentionRulesRequest{NamespaceName: new(target.Namespace), BucketName: new(target.Bucket)})
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

func writeBackup(ctx context.Context, destination io.Writer, dataDir, configPath string, created time.Time) error {
	writer := tar.NewWriter(destination)
	manifest, err := json.Marshal(backupManifest{Version: 1, CreatedAt: created})
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

func backupObjectDigest(object string) (string, error) {
	relative, ok := strings.CutPrefix(object, backupPrefix)
	stamp, digest, found := strings.Cut(relative, "/")
	if !ok || !found {
		return "", errors.New("invalid NetBird recovery object")
	}
	if _, err := time.Parse("20060102T150405.000000000Z", stamp); err != nil {
		return "", errors.New("invalid NetBird recovery timestamp")
	}
	digest, ok = strings.CutSuffix(digest, ".tar")
	wire, err := hex.DecodeString(digest)
	if !ok || err != nil || len(wire) != sha256.Size || hex.EncodeToString(wire) != digest {
		return "", errors.New("invalid NetBird recovery digest")
	}
	return digest, nil
}

// LatestBackup discovers the newest immutable recovery object in an admitted
// region, so replacement hosts need no manually copied backup record.
func LatestBackup(ctx context.Context, target BackupTarget) (BackupRecord, error) {
	var latest BackupRecord
	if err := target.protected(ctx); err != nil {
		return latest, err
	}
	request := objectstorage.ListObjectsRequest{
		NamespaceName: new(target.Namespace), BucketName: new(target.Bucket),
		Prefix: new(backupPrefix), Fields: new("name,size"), Limit: new(1000),
	}
	for {
		response, err := target.Client.ListObjects(ctx, request)
		if err != nil {
			return latest, err
		}
		for _, object := range response.Objects {
			if object.Name == nil || object.Size == nil || *object.Size <= 0 || *object.Size > maxBackupBytes+(16<<20) {
				return latest, errors.New("NetBird recovery inventory has an invalid object")
			}
			if _, err := backupObjectDigest(*object.Name); err != nil {
				return latest, err
			}
			if *object.Name > latest.Object {
				stamp, _, _ := strings.Cut(strings.TrimPrefix(*object.Name, backupPrefix), "/")
				created, err := time.Parse("20060102T150405.000000000Z", stamp)
				if err != nil {
					return latest, err
				}
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
	want, err := backupObjectDigest(object)
	if err != nil {
		return err
	}
	response, err := target.Client.GetObject(ctx, objectstorage.GetObjectRequest{
		NamespaceName: new(target.Namespace), BucketName: new(target.Bucket), ObjectName: new(object),
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
	if err := target.protected(ctx); err != nil {
		return manifestTime, err
	}
	if _, err := os.Lstat(replacementDir); !errors.Is(err, fs.ErrNotExist) {
		return manifestTime, errors.New("NetBird restore requires an absent isolated replacement directory")
	}
	stage, err := os.MkdirTemp(filepath.Dir(replacementDir), ".netbird-restore-*")
	if err != nil {
		return manifestTime, err
	}
	defer os.RemoveAll(stage)
	archive, err := os.CreateTemp(filepath.Dir(replacementDir), ".netbird-restore-*.tar")
	if err != nil {
		return manifestTime, err
	}
	defer func() { err = errors.Join(err, archive.Close(), os.Remove(archive.Name())) }()
	if err := target.download(ctx, object, archive); err != nil {
		return manifestTime, err
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return manifestTime, err
	}
	reader := tar.NewReader(archive)
	header, err := reader.Next()
	if err != nil || header.Name != "manifest.json" || header.Typeflag != tar.TypeReg || header.Size > 4096 {
		return manifestTime, errors.New("NetBird recovery manifest is missing or invalid")
	}
	wire, err := io.ReadAll(reader)
	if err != nil {
		return manifestTime, err
	}
	var manifest backupManifest
	if err := json.Unmarshal(wire, &manifest); err != nil || manifest.Version != 1 || manifest.CreatedAt.IsZero() {
		return manifestTime, errors.New("NetBird recovery manifest version or time is invalid")
	}
	root, err := os.OpenRoot(stage)
	if err != nil {
		return manifestTime, err
	}
	defer root.Close()
	total, stores, config := int64(0), 0, false
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return manifestTime, err
		}
		if err := ctx.Err(); err != nil {
			return manifestTime, err
		}
		total += header.Size
		if header.Typeflag != tar.TypeReg || header.Size < 0 || total > maxBackupBytes || !filepath.IsLocal(header.Name) || filepath.Clean(header.Name) != header.Name ||
			(header.Name != "config.yaml" && !strings.HasPrefix(header.Name, "data/")) {
			return manifestTime, errors.New("NetBird recovery contains an invalid file")
		}
		if err := root.MkdirAll(filepath.Dir(header.Name), 0o700); err != nil {
			return manifestTime, err
		}
		file, err := root.OpenFile(header.Name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return manifestTime, err
		}
		_, copyErr := io.CopyN(file, reader, header.Size)
		if err := errors.Join(copyErr, file.Sync(), file.Close()); err != nil {
			return manifestTime, err
		}
		config = config || header.Name == "config.yaml" && header.Size > 0
		if strings.HasSuffix(header.Name, ".db") && strings.HasPrefix(header.Name, "data/") {
			stores++
		}
	}
	if !config || stores == 0 {
		return manifestTime, errors.New("NetBird recovery lacks config or SQLite identity store")
	}
	if err := unix.Renameat2(unix.AT_FDCWD, stage, unix.AT_FDCWD, replacementDir, unix.RENAME_NOREPLACE); err != nil {
		return manifestTime, fmt.Errorf("install isolated NetBird recovery: %w", err)
	}
	return manifest.CreatedAt, nil
}
