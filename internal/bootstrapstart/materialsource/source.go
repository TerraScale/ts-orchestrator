package materialsource

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"uuid"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
	"golang.org/x/sys/unix"
)

const materialSourceLimit = 8 << 20
const materialSourceSecretLimit = 25 << 10

var ErrMaterialSource = errors.New("regional bootstrap source unavailable or conflicts with authorized installation")

type materialSourceArchive struct {
	SchemaVersion  int               `json:"schemaVersion"`
	Kind           string            `json:"kind,omitempty"`
	BindingSHA256  string            `json:"bindingSha256,omitempty"`
	InstallationID string            `json:"installationId"`
	Cell           string            `json:"cell"`
	Generation     uint64            `json:"generation"`
	PlanSHA256     string            `json:"planSha256"`
	Files          map[string][]byte `json:"files"`
}

type materialSourceReference struct {
	SecretOCID string `json:"secretOcid"`
	SHA256     string `json:"sha256"`
	MaxBytes   int64  `json:"maxBytes"`
}

type materialSourceState struct {
	SchemaVersion  int                           `json:"schemaVersion"`
	Kind           string                        `json:"kind,omitempty"`
	BindingSHA256  string                        `json:"bindingSha256,omitempty"`
	InstallationID string                        `json:"installationId"`
	Cell           string                        `json:"cell"`
	Generation     uint64                        `json:"generation"`
	PlanSHA256     string                        `json:"planSha256"`
	Target         bootstrapmaterial.VaultTarget `json:"target"`
	SecretName     string                        `json:"secretName"`
	RetryToken     string                        `json:"retryToken"`
	StartedAt      time.Time                     `json:"startedAt"`
	Reference      materialSourceReference       `json:"reference"`
	Journal        []byte                        `json:"journal,omitempty"`
}

// ColdStartMaterial retains the one CAS revision authorizing source escrow and
// host publication. Only the founder-only Vault contains the signing source.
type ColdStartMaterial struct {
	grant                     region.VerifiedBootstrapMaterial
	objects                   bootstrapstart.FounderSelectionObjectWriter
	directory, key, etag      string
	kind, binding, secretName string
	link                      *linkInputs
	state                     materialSourceState
	archive                   materialSourceArchive
	record                    bootstrapmaterial.Record
	publication               bootstrapmaterial.Publication
}

func (source *ColdStartMaterial) Record() bootstrapmaterial.Record { return cloneRecord(source.record) }

// ResolveColdStartMaterial reserves the installation before source escrow,
// recovers its exact Vault version, then restores the immutable local producer.
func ResolveColdStartMaterial(ctx context.Context, grant region.VerifiedBootstrapMaterial, objects bootstrapstart.FounderSelectionObjectWriter, management bootstrapmaterial.VaultClient, bundles EscrowClient, directory string, now time.Time) (*ColdStartMaterial, error) {
	cfg := grant.Config()
	if objects == nil || management == nil || bundles == nil || !grant.IsVerified() || now.IsZero() || cfg.Validate() != nil || !now.Before(grant.ExpiresAt()) || ctx.Err() != nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || grant.EscrowTarget().Validate("sa-saopaulo-1") != nil {
		return nil, ErrMaterialSource
	}
	scope := sha256.Sum256([]byte(grant.InstallationID() + "\x00" + cfg.Cell))
	source := &ColdStartMaterial{grant: grant, objects: objects, directory: directory, key: grant.StorageDomain().Prefix + "/bootstrap/v2/material-source/" + hex.EncodeToString(scope[:]) + ".json", secretName: "ts-bootstrap-source-" + hex.EncodeToString(scope[:16])}
	return resolveSource(ctx, source, management, bundles, now)
}

func resolveSource(ctx context.Context, source *ColdStartMaterial, management bootstrapmaterial.VaultClient, bundles EscrowClient, now time.Time) (*ColdStartMaterial, error) {
	grant, cfg := source.grant, source.grant.Config()
	state, etag, err := source.read(ctx)
	if errors.Is(err, os.ErrNotExist) {
		state = materialSourceState{SchemaVersion: 1, InstallationID: grant.InstallationID(), Cell: cfg.Cell, Generation: grant.Generation(), PlanSHA256: grant.PlanDigest(), Target: grant.EscrowTarget(), Kind: source.kind, BindingSHA256: source.binding, SecretName: source.secretName, RetryToken: uuid.New().String(), StartedAt: now.UTC()}
		_, _ = source.write(ctx, state, "")
		state, etag, err = source.read(ctx)
	}
	if err != nil {
		return nil, err
	}
	source.state, source.etag = state, etag
	id, err := source.lookupEscrow(ctx, bundles)
	if err != nil {
		return nil, err
	}
	var candidate []byte
	if id == "" {
		if state.Reference.SecretOCID != "" || now.Before(state.StartedAt) || now.Sub(state.StartedAt) >= 23*time.Hour {
			return nil, ErrMaterialSource
		}
		candidate, err = source.generate(ctx, now)
		if err != nil {
			return nil, err
		}
		defer clear(candidate)
		if source.etag, err = source.write(ctx, state, source.etag); err != nil {
			return nil, err
		}
		encoded := base64.StdEncoding.EncodeToString(candidate)
		response, createErr := management.CreateSecret(ociclient.RequestContext(ctx), ocivault.CreateSecretRequest{CreateSecretDetails: ocivault.CreateSecretDetails{CompartmentId: new(state.Target.CompartmentOCID), VaultId: new(state.Target.VaultOCID), KeyId: new(state.Target.KMSKeyOCID), SecretName: new(state.SecretName), Description: new("Founder-only immutable regional bootstrap source; never deliver to ordinary hosts."), SecretContent: ocivault.Base64SecretContentDetails{Content: new(encoded), Stage: ocivault.SecretContentDetailsStageCurrent}}, OpcRetryToken: new(state.RetryToken)})
		encoded = ""
		if createErr == nil && response.Id != nil {
			id = *response.Id
		} else {
			id, err = source.lookupEscrow(ctx, bundles)
			if err != nil || id == "" {
				return nil, ErrMaterialSource
			}
		}
	}
	body, err := source.readEscrow(ctx, management, bundles, id)
	if err != nil {
		return nil, err
	}
	defer clear(body)
	if len(candidate) > 0 && !bytes.Equal(candidate, body) {
		return nil, ErrMaterialSource
	}
	source.archive, err = source.decodeArchive(body)
	if err != nil {
		return nil, err
	}
	if err := source.restore(ctx); err != nil {
		return nil, err
	}
	if state.Reference.SecretOCID == "" {
		source.state.Reference = materialSourceReference{SecretOCID: id, SHA256: digestWire(body), MaxBytes: int64(len(body))}
		source.etag, err = source.write(ctx, source.state, source.etag)
		if err != nil {
			return nil, err
		}
	}
	return source, nil
}

// Provision checkpoints the original retry identities/timestamps before every
// secret create. Escrow is never included in the ordinary host references.
func (source *ColdStartMaterial) Provision(ctx context.Context, target bootstrapmaterial.VaultTarget, management bootstrapmaterial.VaultClient, bundles bootstrapmaterial.BundleClient, now time.Time) (bootstrapmaterial.Publication, error) {
	if source == nil || !now.Before(source.grant.ExpiresAt()) || source.verifySource(ctx) != nil {
		return bootstrapmaterial.Publication{}, ErrMaterialSource
	}
	provision := bootstrapmaterial.ProvisionDurable
	if source.link != nil {
		provision = bootstrapmaterial.ProvisionLinkDurable
	}
	publication, err := provision(ctx, source.directory, target, management, bundles, now, func(journal []byte) error {
		next := source.state
		next.Journal = bytes.Clone(journal)
		etag, err := source.write(ctx, next, source.etag)
		if err != nil {
			clear(next.Journal)
			return err
		}
		clear(source.state.Journal)
		source.state.Journal = next.Journal
		source.etag = etag
		return nil
	})
	if err != nil {
		return bootstrapmaterial.Publication{}, err
	}
	source.publication = clonePublication(publication)
	return clonePublication(publication), nil
}

func (source *ColdStartMaterial) generate(ctx context.Context, now time.Time) ([]byte, error) {
	parent, err := os.MkdirTemp(filepath.Dir(source.directory), ".material-candidate-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(parent)
	path := filepath.Join(parent, "source")
	var record bootstrapmaterial.Record
	if source.link == nil {
		record, err = bootstrapmaterial.Generate(path, source.grant.Config(), now)
	} else {
		if err := source.link.verify(ctx); err != nil {
			return nil, err
		}
		homeLinkPath := path
		if source.link.homeLink != nil {
			homeLinkPath = source.link.homeLink.source.directory
		}
		var linkRecord bootstrapmaterial.LinkRecord
		linkRecord, err = bootstrapmaterial.GenerateLink(source.link.regional.directory, source.link.home.directory, homeLinkPath, path, now)
		record = linkRecord.Record
	}
	if err != nil {
		return nil, err
	}
	archive := materialSourceArchive{SchemaVersion: 1, Kind: source.kind, BindingSHA256: source.binding, InstallationID: source.grant.InstallationID(), Cell: record.Config.Cell, Generation: source.grant.Generation(), PlanSHA256: source.grant.PlanDigest(), Files: make(map[string][]byte)}
	defer clearArchive(archive)
	names := []string{"material.json", "READY"}
	for _, file := range record.Files {
		names = append(names, file.Name)
	}
	for _, name := range names {
		archive.Files[name], err = os.ReadFile(filepath.Join(path, name))
		if err != nil {
			return nil, err
		}
	}
	wire, err := json.Marshal(archive, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	defer clear(wire)
	if len(wire) > materialSourceLimit {
		return nil, ErrMaterialSource
	}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(wire); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	if compressed.Len() > min(materialSourceSecretLimit, int(bootstrap.MaxSecretBytes)) {
		return nil, ErrMaterialSource
	}
	return compressed.Bytes(), nil
}

func clearArchive(archive materialSourceArchive) {
	for _, body := range archive.Files {
		clear(body)
	}
}

func (source *ColdStartMaterial) decodeArchive(body []byte) (materialSourceArchive, error) {
	reader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return materialSourceArchive{}, ErrMaterialSource
	}
	defer reader.Close()
	wire, err := io.ReadAll(io.LimitReader(reader, materialSourceLimit+1))
	defer clear(wire)
	if err != nil || len(wire) > materialSourceLimit {
		return materialSourceArchive{}, ErrMaterialSource
	}
	var archive materialSourceArchive
	if json.Unmarshal(wire, &archive, json.RejectUnknownMembers(true)) != nil || archive.SchemaVersion != 1 || archive.Kind != source.kind || archive.BindingSHA256 != source.binding || archive.InstallationID != source.grant.InstallationID() || archive.Cell != source.grant.Config().Cell || archive.Generation == 0 || archive.Generation > source.grant.Generation() || archive.PlanSHA256 != source.grant.PlanDigest() || len(archive.Files) < 3 || len(archive.Files) > 66 {
		clearArchive(archive)
		return materialSourceArchive{}, ErrMaterialSource
	}
	return archive, nil
}

type EscrowClient interface {
	bootstrapmaterial.BundleClient
	GetSecretBundleByName(context.Context, ocisecrets.GetSecretBundleByNameRequest) (ocisecrets.GetSecretBundleByNameResponse, error)
}

func (source *ColdStartMaterial) lookupEscrow(ctx context.Context, bundles EscrowClient) (string, error) {
	response, err := bundles.GetSecretBundleByName(ociclient.RequestContext(ctx), ocisecrets.GetSecretBundleByNameRequest{SecretName: new(source.state.SecretName), VaultId: new(source.state.Target.VaultOCID), VersionNumber: new(int64(1))})
	if service, ok := common.IsServiceError(err); ok && service.GetHTTPStatusCode() == 404 {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if response.SecretId == nil || response.VersionNumber == nil || *response.VersionNumber != 1 {
		return "", ErrMaterialSource
	}
	return *response.SecretId, nil
}

func (source *ColdStartMaterial) readEscrow(ctx context.Context, management bootstrapmaterial.VaultClient, bundles bootstrapmaterial.BundleClient, id string) ([]byte, error) {
	target := source.state.Target
	secret, err := management.GetSecret(ociclient.RequestContext(ctx), ocivault.GetSecretRequest{SecretId: new(id)})
	if err != nil || secret.Id == nil || *secret.Id != id || secret.CompartmentId == nil || *secret.CompartmentId != target.CompartmentOCID || secret.VaultId == nil || *secret.VaultId != target.VaultOCID || secret.KeyId == nil || *secret.KeyId != target.KMSKeyOCID || secret.SecretName == nil || *secret.SecretName != source.state.SecretName || secret.CurrentVersionNumber == nil || *secret.CurrentVersionNumber != 1 || secret.LifecycleState != ocivault.SecretLifecycleStateActive {
		return nil, ErrMaterialSource
	}
	response, err := bundles.GetSecretBundle(ociclient.RequestContext(ctx), ocisecrets.GetSecretBundleRequest{SecretId: new(id), VersionNumber: new(int64(1))})
	if err != nil || response.SecretId == nil || *response.SecretId != id || response.VersionNumber == nil || *response.VersionNumber != 1 {
		return nil, ErrMaterialSource
	}
	content, ok := response.SecretBundleContent.(ocisecrets.Base64SecretBundleContentDetails)
	if !ok || content.Content == nil || len(*content.Content) > base64.StdEncoding.EncodedLen(min(materialSourceSecretLimit, int(bootstrap.MaxSecretBytes))) {
		return nil, ErrMaterialSource
	}
	body, err := base64.StdEncoding.Strict().DecodeString(*content.Content)
	ref := source.state.Reference
	if err != nil || len(body) == 0 || len(body) > min(materialSourceSecretLimit, int(bootstrap.MaxSecretBytes)) || ref.SecretOCID != "" && (ref.SecretOCID != id || ref.SHA256 != digestWire(body) || ref.MaxBytes != int64(len(body))) {
		clear(body)
		return nil, ErrMaterialSource
	}
	return body, nil
}

func (source *ColdStartMaterial) read(ctx context.Context) (materialSourceState, string, error) {
	domain := source.grant.StorageDomain()
	response, err := source.objects.GetObject(ociclient.RequestContext(ctx), objectstorage.GetObjectRequest{NamespaceName: new(domain.Namespace), BucketName: new(domain.HeadBucket), ObjectName: new(source.key)})
	if service, ok := common.IsServiceError(err); ok && service.GetHTTPStatusCode() == 404 {
		return materialSourceState{}, "", os.ErrNotExist
	}
	if err != nil {
		return materialSourceState{}, "", err
	}
	if response.Content == nil {
		return materialSourceState{}, "", ErrMaterialSource
	}
	defer response.Content.Close()
	if response.ETag == nil || *response.ETag == "" {
		return materialSourceState{}, "", ErrMaterialSource
	}
	wire, err := io.ReadAll(io.LimitReader(response.Content, 2<<20))
	defer clear(wire)
	if err != nil || len(wire) >= 2<<20 {
		return materialSourceState{}, "", ErrMaterialSource
	}
	var state materialSourceState
	if json.Unmarshal(wire, &state, json.RejectUnknownMembers(true)) != nil || state.SchemaVersion != 1 || state.Kind != source.kind || state.BindingSHA256 != source.binding || state.InstallationID != source.grant.InstallationID() || state.Cell != source.grant.Config().Cell || state.Generation == 0 || state.Generation > source.grant.Generation() || state.PlanSHA256 != source.grant.PlanDigest() || state.Target != source.grant.EscrowTarget() || state.StartedAt.IsZero() || len(state.Journal) > 1<<20 {
		return materialSourceState{}, "", ErrMaterialSource
	}
	if state.SecretName != source.secretName {
		return materialSourceState{}, "", ErrMaterialSource
	}
	if _, err := uuid.Parse(state.RetryToken); err != nil {
		return materialSourceState{}, "", ErrMaterialSource
	}
	ref := state.Reference
	if ref.SecretOCID != "" && (!validDigest(ref.SHA256) || ref.MaxBytes <= 0 || ref.MaxBytes > min(int64(materialSourceSecretLimit), bootstrap.MaxSecretBytes)) || ref.SecretOCID == "" && (ref.SHA256 != "" || ref.MaxBytes != 0 || len(state.Journal) > 0) {
		return materialSourceState{}, "", ErrMaterialSource
	}
	return state, *response.ETag, nil
}

func (source *ColdStartMaterial) write(ctx context.Context, state materialSourceState, etag string) (string, error) {
	if ctx.Err() != nil || !time.Now().Before(source.grant.ExpiresAt()) || source.link != nil && source.link.verify(ctx) != nil {
		return "", ErrMaterialSource
	}
	wire, err := json.Marshal(state, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	defer clear(wire)
	domain := source.grant.StorageDomain()
	policy := common.NoRetryPolicy()
	request := objectstorage.PutObjectRequest{NamespaceName: new(domain.Namespace), BucketName: new(domain.HeadBucket), ObjectName: new(source.key), OpcSseKmsKeyId: new(domain.HeadKMSKeyOCID), ContentLength: new(int64(len(wire))), PutObjectBody: io.NopCloser(bytes.NewReader(wire)), RequestMetadata: common.RequestMetadata{RetryPolicy: &policy}}
	if etag == "" {
		request.IfNoneMatch = new("*")
	} else {
		request.IfMatch = new(etag)
	}
	_, putErr := source.objects.PutObject(ociclient.RequestContext(ctx), request)
	current, currentETag, readErr := source.read(ctx)
	defer clear(current.Journal)
	if readErr != nil {
		return "", fmt.Errorf("%w: write: %v; readback: %v", ErrMaterialSource, putErr, readErr)
	}
	actual, err := json.Marshal(current, json.Deterministic(true))
	defer clear(actual)
	if err != nil || !bytes.Equal(actual, wire) {
		return "", ErrMaterialSource
	}
	return currentETag, nil
}

func (source *ColdStartMaterial) restore(ctx context.Context) error {
	parent, err := os.MkdirTemp(filepath.Dir(source.directory), ".material-restore-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(parent)
	for name, body := range source.archive.Files {
		if (name == "" || name == "." || name == "..") || filepath.Base(name) != name || strings.ContainsAny(name, "/\\") || len(body) == 0 || len(body) > 1<<20 || name == "publication.json" || name == "publication.lock" || name == ".publication.tmp" {
			return ErrMaterialSource
		}
		if err := writeSourceFile(filepath.Join(parent, name), body); err != nil {
			return err
		}
	}
	record, err := source.loadRecord(parent)
	if err != nil {
		return err
	}
	configWire, err := json.Marshal(record.Config, json.Deterministic(true))
	if err != nil || digestWire(configWire) != source.grant.PlanDigest() || !time.Now().Before(record.ExpiresAt) {
		return ErrMaterialSource
	}
	if len(source.state.Journal) > 0 {
		if err := writeSourceFile(filepath.Join(parent, "publication.json"), source.state.Journal); err != nil {
			return err
		}
	}
	if _, err := os.Lstat(source.directory); err == nil {
		if err := source.restoreJournal(ctx); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else {
		if err := syncSourceDirectory(parent); err != nil {
			return err
		}
		if err := os.Rename(parent, source.directory); err != nil {
			return err
		}
		if err := syncSourceDirectory(filepath.Dir(source.directory)); err != nil {
			return err
		}
	}
	source.record = record
	return nil
}

func (source *ColdStartMaterial) restoreJournal(ctx context.Context) error {
	dir, err := openSourceDirectory(source.directory)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	lock, err := unix.Openat(dir, "publication.lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	defer unix.Close(lock)
	var stat unix.Stat_t
	if err := unix.Fstat(lock, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 || stat.Nlink != 1 || stat.Uid != uint32(os.Getuid()) {
		return ErrMaterialSource
	}
	if err := unix.Flock(lock, unix.LOCK_EX); err != nil {
		return err
	}
	defer unix.Flock(lock, unix.LOCK_UN)
	if err := source.refresh(ctx); err != nil {
		return err
	}
	archive := source.archive
	for name, body := range archive.Files {
		var stat unix.Stat_t
		if err := unix.Fstatat(dir, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err == nil {
			if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 || stat.Mode&0o777 != 0o600 {
				return ErrMaterialSource
			}
		} else if !errors.Is(err, unix.ENOENT) {
			return err
		}
		file, err := os.CreateTemp(filepath.Dir(source.directory), ".restore-material-")
		if err != nil {
			return err
		}
		temporary := file.Name()
		if _, err := file.Write(body); err != nil {
			file.Close()
			os.Remove(file.Name())
			return err
		}
		if err := file.Sync(); err != nil {
			file.Close()
			os.Remove(file.Name())
			return err
		}
		if err := file.Close(); err != nil {
			os.Remove(file.Name())
			return err
		}
		if err := unix.Renameat(unix.AT_FDCWD, temporary, dir, name); err != nil {
			os.Remove(file.Name())
			return err
		}
	}
	if _, err := source.loadRecord(source.directory); err != nil {
		return err
	}
	if len(source.state.Journal) == 0 {
		if err := unix.Unlinkat(dir, "publication.json", 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return err
		}
		return unix.Fsync(dir)
	}
	file, err := os.CreateTemp(filepath.Dir(source.directory), ".restore-journal-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(source.state.Journal); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := unix.Renameat(unix.AT_FDCWD, file.Name(), dir, "publication.json"); err != nil {
		return err
	}
	return unix.Fsync(dir)
}

func writeSourceFile(path string, body []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(body); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func syncSourceDirectory(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func (source *ColdStartMaterial) refresh(ctx context.Context) error {
	state, etag, err := source.read(ctx)
	if err != nil {
		return err
	}
	if state.Reference != source.state.Reference {
		clear(state.Journal)
		return ErrMaterialSource
	}
	clear(source.state.Journal)
	source.state, source.etag = state, etag
	return nil
}

// VerifiedColdStartMaterial exposes only source-verified rendering inputs.
// Host identity, role, artifacts, regional Vault ownership and admission remain the installer's checks.
type VerifiedColdStartMaterial struct {
	source      *ColdStartMaterial
	etag        string
	record      bootstrapmaterial.Record
	publication bootstrapmaterial.Publication
}

func (source *ColdStartMaterial) InstallMaterial(ctx context.Context) (VerifiedColdStartMaterial, error) {
	if source == nil || source.publication.SchemaVersion != 1 || len(source.publication.References) == 0 {
		return VerifiedColdStartMaterial{}, ErrMaterialSource
	}
	verified := VerifiedColdStartMaterial{source: source, etag: source.etag, record: cloneRecord(source.record), publication: clonePublication(source.publication)}
	if err := verified.VerifyCurrent(ctx); err != nil {
		return VerifiedColdStartMaterial{}, err
	}
	return verified, nil
}
func (verified VerifiedColdStartMaterial) IsVerified() bool {
	return verified.source != nil && verified.etag != ""
}
func (verified VerifiedColdStartMaterial) Record() bootstrapmaterial.Record {
	record := verified.record
	record.Config.Slots = slices.Clone(record.Config.Slots)
	record.Files = slices.Clone(record.Files)
	return record
}
func (verified VerifiedColdStartMaterial) Publication() bootstrapmaterial.Publication {
	publication := verified.publication
	publication.References = slices.Clone(publication.References)
	return publication
}
func (verified VerifiedColdStartMaterial) Grant() region.VerifiedBootstrapMaterial {
	if verified.source == nil {
		return region.VerifiedBootstrapMaterial{}
	}
	return verified.source.grant
}
func (verified VerifiedColdStartMaterial) VerifyCurrent(ctx context.Context) error {
	if !verified.IsVerified() || !time.Now().Before(verified.source.grant.ExpiresAt()) || verified.source.link != nil && verified.source.link.verify(ctx) != nil {
		return ErrMaterialSource
	}
	state, etag, err := verified.source.read(ctx)
	defer clear(state.Journal)
	if err != nil || etag != verified.etag || state.Reference != verified.source.state.Reference {
		return ErrMaterialSource
	}
	want, err := json.Marshal(verified.source.state, json.Deterministic(true))
	defer clear(want)
	actual, actualErr := json.Marshal(state, json.Deterministic(true))
	defer clear(actual)
	record, recordErr := verified.source.loadRecord(verified.source.directory)
	recordWire, recordEncodeErr := json.Marshal(record, json.Deterministic(true))
	expectedRecord, expectedRecordErr := json.Marshal(verified.record, json.Deterministic(true))
	if err != nil || actualErr != nil || !bytes.Equal(want, actual) || recordErr != nil || recordEncodeErr != nil || expectedRecordErr != nil || !bytes.Equal(recordWire, expectedRecord) {
		return ErrMaterialSource
	}
	metadata, err := os.ReadFile(filepath.Join(verified.source.directory, "material.json"))
	if err != nil || digestWire(metadata) != verified.publication.MaterialSHA256 || verified.source.validatePublication(verified.publication, state.Journal) != nil {
		return ErrMaterialSource
	}
	return nil
}

func digestWire(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }
func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && value == strings.ToLower(value)
}
func openSourceDirectory(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Uid != uint32(os.Getuid()) || stat.Gid != uint32(os.Getgid()) || stat.Mode&0o777 != 0o700 {
		unix.Close(fd)
		return -1, ErrMaterialSource
	}
	return fd, nil
}

func cloneRecord(record bootstrapmaterial.Record) bootstrapmaterial.Record {
	record.Config.Slots = slices.Clone(record.Config.Slots)
	record.Files = slices.Clone(record.Files)
	return record
}
func clonePublication(publication bootstrapmaterial.Publication) bootstrapmaterial.Publication {
	publication.References = slices.Clone(publication.References)
	return publication
}
