package materialsource

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"uuid"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
	"golang.org/x/sys/unix"
)

const originalSourceKind = "original-source-archive/v1"
const originalSourceStateLimit = 2 << 20
const originalCandidateName = "original-candidate.gz"

type originalSourceCandidate struct {
	SHA256       string `json:"sha256"`
	MaxBytes     int64  `json:"maxBytes"`
	CreateSHA256 string `json:"createSha256"`
}

// Schema 3 is deliberately separate from the normal founder's schema 1.
// Its public inventory is DATA and cannot grant startup or runtime identity.
type originalSourceState struct {
	SchemaVersion                int                               `json:"schemaVersion"`
	Kind                         string                            `json:"kind"`
	Scope                        region.OriginalSourceActorScope   `json:"scope"`
	IntentSHA256                 string                            `json:"intentSha256"`
	AdmissionAuthorizationSHA256 string                            `json:"admissionAuthorizationSha256"`
	Target                       bootstrapmaterial.VaultTarget     `json:"target"`
	SecretName                   string                            `json:"secretName"`
	RetryToken                   string                            `json:"retryToken"`
	StartedAt                    time.Time                         `json:"startedAt"`
	Candidate                    originalSourceCandidate           `json:"candidate"`
	Reference                    materialSourceReference           `json:"reference"`
	OriginalAdmissionInventory   []byte                            `json:"originalAdmissionInventory,omitempty"`
	Publication                  *originalMaterialPublicationState `json:"publication,omitempty"`
	Startup                      map[string][]byte                 `json:"startup,omitempty"`
	SeedCompletion               []byte                            `json:"seedCompletion,omitempty"`
}

type originalSourceInputs struct {
	scope                   region.OriginalSourceActorScope
	intent                  region.OriginalSourceProducerIntent
	config                  bootstrapmaterial.Config
	admission               release.AdmissionAttestorAuthorization
	intentSHA, admissionSHA string
}

type originalSourceClients struct {
	objects    *objectstorage.ObjectStorageClient
	management *ocivault.VaultsClient
	bundles    *ocisecrets.SecretsClient
}

// VerifiedOriginalSourceArchive proves only the original archive selection.
// It is never a normal founder, startup template, installation or publication.
type VerifiedOriginalSourceArchive struct {
	actor           region.VerifiedOriginalSourceActor
	inputs          originalSourceInputs
	state           originalSourceState
	etag, directory string
}

func (v VerifiedOriginalSourceArchive) IsVerified() bool {
	return v.actor.IsVerified() && v.etag != "" && v.state.Reference.SecretOCID != "" && len(v.state.OriginalAdmissionInventory) != 0
}

func originalInputs(ctx context.Context, actor region.VerifiedOriginalSourceActor) (originalSourceInputs, error) {
	var in originalSourceInputs
	if !actor.IsVerified() || actor.Guard(ctx) != nil {
		return in, ErrMaterialSource
	}
	in.scope, in.intent, in.config = actor.Scope(), actor.OriginalIntent(), actor.Config()
	var err error
	in.admission, err = actor.AdmissionAttestor(ctx)
	wire, encodeErr := json.Marshal(in.intent, json.Deterministic(true))
	in.intentSHA = digestWire(wire)
	in.admissionSHA, _ = in.admission.Digest()
	config, configErr := json.Marshal(in.config, json.Deterministic(true))
	q, s := in.intent, in.scope
	if err != nil || encodeErr != nil || configErr != nil || in.config.Validate() != nil || !validDigest(s.SHA256) || !time.Now().Before(s.Deadline) ||
		s.InstanceID == "" || s.Cell != q.Cell || s.InstallationID != q.InstallationID || s.Generation != q.Generation || s.PlanSHA256 != q.PlanSHA256 || digestWire(config) != q.PlanSHA256 ||
		in.config.Cell != strings.ToLower(q.Cell) || q.Home.Validate() != nil || q.Home.HeadBucket != "gru-1-head" || q.Escrow.Validate("sa-saopaulo-1") != nil ||
		q.AdmissionAuthorizationSHA256 != in.admissionSHA || in.admission.SourceNamespace != q.Home.Namespace || in.admission.SourceBucket != q.Home.HeadBucket || in.admission.SourceObject != q.SourceObject {
		return originalSourceInputs{}, ErrMaterialSource
	}
	return in, nil
}

func originalClients(ctx context.Context, actor region.VerifiedOriginalSourceActor) (originalSourceClients, context.Context, error) {
	var clients originalSourceClients
	factory, guarded, err := actor.GuardedFactory(ctx)
	if err != nil {
		return clients, ctx, err
	}
	home, err := factory.ForRegion("sa-saopaulo-1")
	if err != nil {
		return clients, ctx, err
	}
	objects, err := home.ObjectStorage()
	if err != nil {
		return clients, ctx, err
	}
	management, err := ocivault.NewVaultsClientWithConfigurationProvider(home.Provider())
	if err != nil {
		return clients, ctx, err
	}
	management.SetRegion("sa-saopaulo-1")
	home.Configure(&management.BaseClient, ociclient.ServiceVault)
	bundles, err := vaultsecret.SecretsClient(home)
	if err != nil {
		return clients, ctx, err
	}
	return originalSourceClients{&objects, &management, &bundles}, ociclient.WithRequestGuard(guarded, actor.Guard), nil
}

func originalState(in originalSourceInputs, now time.Time) originalSourceState {
	return originalSourceState{SchemaVersion: 3, Kind: originalSourceKind, Scope: in.scope, IntentSHA256: in.intentSHA,
		AdmissionAuthorizationSHA256: in.admissionSHA, Target: in.intent.Escrow, SecretName: in.intent.SourceSecretName,
		RetryToken: uuid.New().String(), StartedAt: now.UTC()}
}

func validOriginalState(state originalSourceState, in originalSourceInputs) bool {
	if state.SchemaVersion != 3 || state.Kind != originalSourceKind || state.Scope != in.scope || state.IntentSHA256 != in.intentSHA ||
		state.AdmissionAuthorizationSHA256 != in.admissionSHA || state.Target != in.intent.Escrow || state.SecretName != in.intent.SourceSecretName ||
		state.StartedAt.IsZero() || state.StartedAt.After(time.Now()) || !state.StartedAt.Before(in.scope.Deadline) || len(state.OriginalAdmissionInventory) > bootstrap.MaxManifestBytes || !validOriginalPublication(state, in) || !validOriginalStartupState(state, in) {
		return false
	}
	if id, err := uuid.Parse(state.RetryToken); err != nil || id.String() != state.RetryToken {
		return false
	}
	c, r := state.Candidate, state.Reference
	if c == (originalSourceCandidate{}) {
		return r == (materialSourceReference{}) && len(state.OriginalAdmissionInventory) == 0 && state.Publication == nil
	}
	if !validDigest(c.SHA256) || !validDigest(c.CreateSHA256) || c.MaxBytes <= 0 || c.MaxBytes > materialSourceSecretLimit {
		return false
	}
	if r == (materialSourceReference{}) {
		return len(state.OriginalAdmissionInventory) == 0 && state.Publication == nil
	}
	return originalSecretID(r.SecretOCID) && r.SHA256 == c.SHA256 && r.MaxBytes == c.MaxBytes
}

func immutableOriginalState(prior, next originalSourceState) bool {
	a, b := prior, next
	a.Candidate, b.Candidate = originalSourceCandidate{}, originalSourceCandidate{}
	a.Reference, b.Reference = materialSourceReference{}, materialSourceReference{}
	a.OriginalAdmissionInventory, b.OriginalAdmissionInventory = nil, nil
	a.Publication, b.Publication = nil, nil
	a.Startup, b.Startup, a.SeedCompletion, b.SeedCompletion = nil, nil, nil, nil
	if !sameOriginalState(a, b) || !immutableOriginalPublication(prior, next) || !immutableOriginalStartup(prior, next) || prior.Candidate != (originalSourceCandidate{}) && prior.Candidate != next.Candidate ||
		prior.Reference != (materialSourceReference{}) && prior.Reference != next.Reference ||
		len(prior.OriginalAdmissionInventory) != 0 && !bytes.Equal(prior.OriginalAdmissionInventory, next.OriginalAdmissionInventory) {
		return false
	}
	// Candidate, exact Vault-v1 reference and inventory each need a prior CAS.
	return (next.Reference == (materialSourceReference{}) || prior.Candidate != (originalSourceCandidate{})) &&
		(len(next.OriginalAdmissionInventory) == 0 || prior.Reference != (materialSourceReference{}))
}

func sameOriginalState(a, b originalSourceState) bool {
	x, err := json.Marshal(a, json.Deterministic(true))
	y, other := json.Marshal(b, json.Deterministic(true))
	return err == nil && other == nil && bytes.Equal(x, y)
}

func readOriginalState(ctx context.Context, objects *objectstorage.ObjectStorageClient, in originalSourceInputs) (originalSourceState, string, error) {
	var state originalSourceState
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	q := in.intent
	policy := common.NoRetryPolicy()
	response, err := objects.GetObject(ociclient.RequestContext(ctx), objectstorage.GetObjectRequest{NamespaceName: new(q.Home.Namespace), BucketName: new(q.Home.HeadBucket), ObjectName: new(q.SourceObject), RequestMetadata: common.RequestMetadata{RetryPolicy: &policy}})
	if service, ok := common.IsServiceError(err); ok && service.GetHTTPStatusCode() == 404 {
		return state, "", os.ErrNotExist
	}
	if err != nil {
		return state, "", err
	}
	if response.Content == nil {
		return state, "", ErrMaterialSource
	}
	defer response.Content.Close()
	etag := derefOriginal(response.ETag)
	wire, err := io.ReadAll(io.LimitReader(response.Content, originalSourceStateLimit+1))
	if err != nil {
		// Keep a cancelled or expired dispatch distinguishable from bad state.
		return originalSourceState{}, "", errors.Join(ErrMaterialSource, err)
	}
	if len(wire) > originalSourceStateLimit || etag == "" || len(etag) > 1024 || strings.ContainsAny(etag, "\x00\r\n") ||
		json.Unmarshal(wire, &state, json.RejectUnknownMembers(true)) != nil || !validOriginalState(state, in) {
		return originalSourceState{}, "", ErrMaterialSource
	}
	canonical, err := json.Marshal(state, json.Deterministic(true))
	if err != nil || !bytes.Equal(canonical, wire) {
		return originalSourceState{}, "", ErrMaterialSource
	}
	return state, etag, nil
}

func writeOriginalState(ctx, readbackCtx context.Context, objects *objectstorage.ObjectStorageClient, in originalSourceInputs, state originalSourceState, etag string) (string, error) {
	if !validOriginalState(state, in) {
		return "", ErrMaterialSource
	}
	if etag == "" {
		if state.Candidate != (originalSourceCandidate{}) || state.Reference != (materialSourceReference{}) || len(state.OriginalAdmissionInventory) != 0 {
			return "", ErrMaterialSource
		}
	} else {
		prior, observed, err := readOriginalState(ctx, objects, in)
		if err != nil || observed != etag || !immutableOriginalState(prior, state) {
			return "", ErrMaterialSource
		}
	}
	wire, err := json.Marshal(state, json.Deterministic(true))
	if err != nil || len(wire) > originalSourceStateLimit {
		return "", ErrMaterialSource
	}
	q := in.intent
	policy := common.NoRetryPolicy()
	request := objectstorage.PutObjectRequest{NamespaceName: new(q.Home.Namespace), BucketName: new(q.Home.HeadBucket), ObjectName: new(q.SourceObject), OpcSseKmsKeyId: new(q.Home.HeadKMSKeyOCID), ContentLength: new(int64(len(wire))), PutObjectBody: io.NopCloser(bytes.NewReader(wire)), RequestMetadata: common.RequestMetadata{RetryPolicy: &policy}}
	if etag == "" {
		request.IfNoneMatch = new("*")
	} else {
		request.IfMatch = new(etag)
	}
	writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	_, _ = objects.PutObject(ociclient.RequestContext(writeCtx), request)
	cancel()
	// The effect guard binds the PREVIOUS revision. Independent readback keeps
	// the actor guard but cannot require that superseded revision after the CAS.
	current, currentETag, err := readOriginalState(readbackCtx, objects, in)
	if err != nil || !sameOriginalState(current, state) {
		return "", errors.Join(ErrMaterialSource, err)
	}
	return currentETag, nil
}

func originalCreateRequest(state originalSourceState, body []byte) ocivault.CreateSecretRequest {
	return originalEscrowRequest(state.Target, state.SecretName, state.RetryToken, body)
}

func originalEscrowRequest(target bootstrapmaterial.VaultTarget, name, token string, body []byte) ocivault.CreateSecretRequest {
	policy := common.NoRetryPolicy()
	return ocivault.CreateSecretRequest{CreateSecretDetails: ocivault.CreateSecretDetails{CompartmentId: new(target.CompartmentOCID), VaultId: new(target.VaultOCID), KeyId: new(target.KMSKeyOCID), SecretName: new(name),
		Description:   new("Founder-only immutable original regional bootstrap source; never deliver to ordinary hosts."),
		SecretContent: ocivault.Base64SecretContentDetails{Content: new(base64.StdEncoding.EncodeToString(body)), Stage: ocivault.SecretContentDetailsStageCurrent}},
		OpcRetryToken: new(token), RequestMetadata: common.RequestMetadata{RetryPolicy: &policy}}
}

func originalCreateSHA(state originalSourceState, body []byte) (string, error) {
	return originalEscrowSHA(state.Target, state.SecretName, state.RetryToken, body)
}

func originalEscrowSHA(target bootstrapmaterial.VaultTarget, name, token string, body []byte) (string, error) {
	r, err := originalEscrowRequest(target, name, token, body).HTTPRequest(http.MethodPost, "/20180608/secrets", nil, nil)
	if err != nil || r.Body == nil {
		return "", ErrMaterialSource
	}
	defer r.Body.Close()
	wire, err := io.ReadAll(io.LimitReader(r.Body, 128<<10))
	defer clear(wire)
	var data map[string]any
	if err != nil || len(wire) >= 128<<10 || json.Unmarshal(wire, &data) != nil {
		return "", ErrMaterialSource
	}
	canonical, err := json.Marshal(data, json.Deterministic(true))
	defer clear(canonical)
	if err != nil {
		return "", err
	}
	bound := append([]byte(token+"\x00"), canonical...)
	defer clear(bound)
	return digestWire(bound), nil
}

func originalSecretID(id string) bool {
	const prefix = "ocid1.vaultsecret.oc1.sa-saopaulo-1."
	if !strings.HasPrefix(id, prefix) || len(id) <= len(prefix) || len(id) > 512 {
		return false
	}
	for _, char := range id[len(prefix):] {
		if char != '.' && (char < 'a' || char > 'z') && (char < '0' || char > '9') {
			return false
		}
	}
	return true
}

// Recovery uses the exact named version, then independently reads its metadata.
// No list, latest-version, or caller-selected secret ID is accepted.
func readOriginalVault(ctx context.Context, clients originalSourceClients, state originalSourceState) ([]byte, string, error) {
	return readOriginalEscrow(ctx, clients, state.Target, state.SecretName, state.RetryToken, state.Candidate, state.Reference)
}

func readOriginalEscrow(ctx context.Context, clients originalSourceClients, target bootstrapmaterial.VaultTarget, name, token string, candidate originalSourceCandidate, reference materialSourceReference) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	policy := common.NoRetryPolicy()
	response, err := clients.bundles.GetSecretBundleByName(ociclient.RequestContext(ctx), ocisecrets.GetSecretBundleByNameRequest{SecretName: new(name), VaultId: new(target.VaultOCID), VersionNumber: new(int64(1)), RequestMetadata: common.RequestMetadata{RetryPolicy: &policy}})
	if service, ok := common.IsServiceError(err); ok && service.GetHTTPStatusCode() == 404 {
		return nil, "", os.ErrNotExist
	}
	if err != nil {
		return nil, "", err
	}
	id := derefOriginal(response.SecretId)
	if !originalSecretID(id) || response.VersionNumber == nil || *response.VersionNumber != 1 {
		return nil, "", ErrMaterialSource
	}
	content, ok := response.SecretBundleContent.(ocisecrets.Base64SecretBundleContentDetails)
	if !ok || content.Content == nil || len(*content.Content) > base64.StdEncoding.EncodedLen(materialSourceSecretLimit) {
		return nil, "", ErrMaterialSource
	}
	body, err := base64.StdEncoding.Strict().DecodeString(*content.Content)
	if err != nil || len(body) == 0 || len(body) > materialSourceSecretLimit {
		clear(body)
		return nil, "", ErrMaterialSource
	}
	secret, err := clients.management.GetSecret(ociclient.RequestContext(ctx), ocivault.GetSecretRequest{SecretId: new(id), RequestMetadata: common.RequestMetadata{RetryPolicy: &policy}})
	if err != nil || derefOriginal(secret.Id) != id || derefOriginal(secret.CompartmentId) != target.CompartmentOCID || derefOriginal(secret.VaultId) != target.VaultOCID ||
		derefOriginal(secret.KeyId) != target.KMSKeyOCID || derefOriginal(secret.SecretName) != name || secret.LifecycleState != ocivault.SecretLifecycleStateActive || secret.CurrentVersionNumber == nil || *secret.CurrentVersionNumber != 1 {
		clear(body)
		return nil, "", errors.Join(ErrMaterialSource, err)
	}
	if candidate == (originalSourceCandidate{}) || digestWire(body) != candidate.SHA256 || int64(len(body)) != candidate.MaxBytes ||
		reference != (materialSourceReference{}) && reference != (materialSourceReference{SecretOCID: id, SHA256: digestWire(body), MaxBytes: int64(len(body))}) {
		clear(body)
		return nil, "", ErrMaterialSource
	}
	requestSHA, err := originalEscrowSHA(target, name, token, body)
	if err != nil || requestSHA != candidate.CreateSHA256 {
		clear(body)
		return nil, "", ErrMaterialSource
	}
	return body, id, nil
}

func derefOriginal(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func lockOriginalDirectory(directory string) (int, func(), error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return -1, nil, ErrMaterialSource
	}
	// The root caller supplies a fixed private path; reject a substituted or
	// writable ancestor before creating any directory or lock below it.
	for parent := filepath.Dir(directory); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err == nil {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !info.IsDir() || !ok || stat.Uid != 0 && stat.Uid != uint32(os.Getuid()) || info.Mode().Perm()&0o022 != 0 && !(stat.Uid == 0 && info.Mode()&os.ModeSticky != 0) {
				return -1, nil, ErrMaterialSource
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return -1, nil, err
		}
		if parent == string(filepath.Separator) {
			break
		}
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return -1, nil, err
	}
	dir, err := openSourceDirectory(directory)
	if err != nil {
		return -1, nil, err
	}
	lock, err := unix.Openat(dir, "original-source.lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		unix.Close(dir)
		return -1, nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(lock, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 || stat.Nlink != 1 || stat.Uid != uint32(os.Getuid()) {
		unix.Close(lock)
		unix.Close(dir)
		return -1, nil, ErrMaterialSource
	}
	if err := unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		unix.Close(lock)
		unix.Close(dir)
		return -1, nil, ErrMaterialSource
	}
	return dir, func() { unix.Flock(lock, unix.LOCK_UN); unix.Close(lock); unix.Close(dir) }, nil
}

func readOriginalCandidate(dir int) ([]byte, error) {
	fd, err := unix.Openat(dir, originalCandidateName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), originalCandidateName)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 || stat.Nlink != 1 || stat.Uid != uint32(os.Getuid()) || stat.Size <= 0 || stat.Size > materialSourceSecretLimit {
		return nil, ErrMaterialSource
	}
	body, err := io.ReadAll(io.LimitReader(file, materialSourceSecretLimit+1))
	if err != nil || len(body) > materialSourceSecretLimit {
		clear(body)
		return nil, ErrMaterialSource
	}
	return body, nil
}

func originalReservationSHA(state originalSourceState) string {
	state.Candidate, state.Reference, state.OriginalAdmissionInventory, state.Publication = originalSourceCandidate{}, materialSourceReference{}, nil, nil
	state.Startup, state.SeedCompletion = nil, nil
	wire, _ := json.Marshal(state, json.Deterministic(true))
	return digestWire(wire)
}

func generateOriginalCandidate(directory string, in originalSourceInputs, state originalSourceState) ([]byte, error) {
	path := filepath.Join(directory, "candidate")
	record, err := bootstrapmaterial.GenerateAdmissionCandidate(path, in.config, in.admission, state.StartedAt)
	if err != nil || !record.IssuedAt.Equal(state.StartedAt) {
		return nil, ErrMaterialSource
	}
	archive := materialSourceArchive{SchemaVersion: 3, Kind: originalSourceKind, BindingSHA256: originalReservationSHA(state), InstallationID: in.scope.InstallationID, Cell: in.config.Cell, Generation: in.scope.Generation, PlanSHA256: in.scope.PlanSHA256, Files: map[string][]byte{}}
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
	defer clear(wire)
	if err != nil || len(wire) > materialSourceLimit {
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
	if compressed.Len() == 0 || compressed.Len() > materialSourceSecretLimit {
		return nil, ErrMaterialSource
	}
	return compressed.Bytes(), nil
}

func persistOriginalCandidate(directory string, dir int, body []byte) error {
	if len(body) == 0 || len(body) > materialSourceSecretLimit {
		return ErrMaterialSource
	}
	file, err := os.CreateTemp(directory, ".original-candidate-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(body); err != nil {
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
	if err := unix.Renameat2(unix.AT_FDCWD, file.Name(), dir, originalCandidateName, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	return unix.Fsync(dir)
}

func decodeOriginalCandidate(directory string, in originalSourceInputs, state originalSourceState, body []byte) (materialSourceArchive, bootstrapmaterial.Record, error) {
	var archive materialSourceArchive
	var record bootstrapmaterial.Record
	reader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return archive, record, ErrMaterialSource
	}
	wire, err := io.ReadAll(io.LimitReader(reader, materialSourceLimit+1))
	closeErr := reader.Close()
	defer clear(wire)
	if err != nil || closeErr != nil || len(wire) > materialSourceLimit || json.Unmarshal(wire, &archive, json.RejectUnknownMembers(true)) != nil ||
		archive.SchemaVersion != 3 || archive.Kind != originalSourceKind || archive.BindingSHA256 != originalReservationSHA(state) || archive.InstallationID != in.scope.InstallationID || archive.Cell != in.config.Cell || archive.Generation != in.scope.Generation || archive.PlanSHA256 != in.scope.PlanSHA256 || len(archive.Files) < 3 || len(archive.Files) > 66 {
		clearArchive(archive)
		return materialSourceArchive{}, record, ErrMaterialSource
	}
	parent, err := os.MkdirTemp(directory, ".original-readback-")
	if err != nil {
		clearArchive(archive)
		return materialSourceArchive{}, record, err
	}
	defer os.RemoveAll(parent)
	for name, data := range archive.Files {
		if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, "/\\") || len(data) == 0 || len(data) > 1<<20 {
			clearArchive(archive)
			return materialSourceArchive{}, record, ErrMaterialSource
		}
		if err := writeSourceFile(filepath.Join(parent, name), data); err != nil {
			clearArchive(archive)
			return materialSourceArchive{}, record, err
		}
	}
	record, err = bootstrapmaterial.Load(parent)
	config, configErr := json.Marshal(record.Config, json.Deterministic(true))
	if err != nil || configErr != nil || digestWire(config) != in.scope.PlanSHA256 || !record.IssuedAt.Equal(state.StartedAt) || record.Public.AdmissionAttestor.AuthorizationSHA256 != in.admissionSHA || bootstrapmaterial.ValidateAdmissionInventory(record) != nil || !time.Now().Before(record.ExpiresAt) || len(archive.Files) != len(record.Files)+2 {
		clearArchive(archive)
		return materialSourceArchive{}, bootstrapmaterial.Record{}, ErrMaterialSource
	}
	return archive, record, nil
}

func originalInventory(in originalSourceInputs, state originalSourceState, archive materialSourceArchive, record bootstrapmaterial.Record) ([]byte, error) {
	key := archive.Files["founder-ledger.key"]
	if len(key) != ed25519.PrivateKeySize || base64.StdEncoding.EncodeToString(ed25519.PrivateKey(key).Public().(ed25519.PublicKey)) != record.Public.LedgerSignerPublicKey {
		return nil, ErrMaterialSource
	}
	binding := bootstrap.RegionalSourceInventory{SchemaVersion: 1, Actor: bootstrap.SourceInventoryActor{InstanceID: in.scope.InstanceID, GrantDigest: in.scope.GrantSHA256, TemplateDigest: in.scope.TemplateSHA256}, GrantSHA256: in.scope.GrantSHA256, PlanSHA256: in.scope.PlanSHA256, SourceSHA256: state.Reference.SHA256, MaterialRecord: bytes.Clone(archive.Files["material.json"])}
	payload, err := trust.EncodePayload(binding)
	if err != nil {
		return nil, err
	}
	scope := trust.Scope{Domain: "terrascale.bootstrap.source-inventory", DeploymentID: in.config.DeploymentID, Cell: strings.ToUpper(in.config.Cell), Environment: in.config.Environment, Role: "source", Slot: in.scope.InstallationID}
	if len(state.OriginalAdmissionInventory) != 0 {
		envelope, err := trust.DecodeEnvelope(state.OriginalAdmissionInventory)
		public := ed25519.PrivateKey(key).Public().(ed25519.PublicKey)
		id, _ := trust.KeyID(public)
		if err != nil || !bytes.Equal(envelope.Payload, payload) {
			return nil, ErrMaterialSource
		}
		if _, err := trust.VerifyHistorical(envelope, scope, trust.Keyring{id: public}, bootstrap.ManifestTrustPolicy()); err != nil {
			return nil, err
		}
		return bytes.Clone(state.OriginalAdmissionInventory), nil
	}
	expires := minOriginalTime(in.scope.Deadline, record.ExpiresAt)
	expires = minOriginalTime(expires, record.IssuedAt.Add(bootstrap.MaxManifestLifetime))
	if !time.Now().Before(expires) || !expires.After(record.IssuedAt) {
		return nil, ErrMaterialSource
	}
	envelope, err := trust.Sign(payload, scope, record.IssuedAt, expires, ed25519.PrivateKey(key))
	if err != nil {
		return nil, err
	}
	return trust.EncodeEnvelope(envelope)
}

func minOriginalTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// ResolveOriginalSourceArchive is the genuine original actor's first source
// effect. Each durable transition is acknowledged before the next effect.
func ResolveOriginalSourceArchive(ctx context.Context, actor region.VerifiedOriginalSourceActor, directory string, now time.Time) (VerifiedOriginalSourceArchive, error) {
	var verified VerifiedOriginalSourceArchive
	if ctx == nil || ctx.Err() != nil || now.IsZero() {
		return verified, ErrMaterialSource
	}
	in, err := originalInputs(ctx, actor)
	if err != nil {
		return verified, err
	}
	clients, guarded, err := originalClients(ctx, actor)
	if err != nil {
		return verified, err
	}
	actorCtx := guarded
	dir, unlock, err := lockOriginalDirectory(directory)
	if err != nil {
		return verified, err
	}
	defer unlock()
	state, etag, err := readOriginalState(guarded, clients.objects, in)
	if errors.Is(err, os.ErrNotExist) {
		state = originalState(in, now)
		etag, err = writeOriginalState(guarded, actorCtx, clients.objects, in, state, "")
	}
	if err != nil {
		return verified, err
	}
	// Every scoped request rechecks both the sealed actor and this exact CAS.
	guard := func(dispatch context.Context) error {
		check := ociclient.CheckpointContext(dispatch)
		if err := actor.Guard(check); err != nil {
			return err
		}
		current, observed, err := readOriginalState(check, clients.objects, in)
		if err != nil || observed != etag || !sameOriginalState(current, state) {
			return errors.Join(ErrMaterialSource, err)
		}
		return ociclient.LimitAdmission(dispatch, in.scope.Deadline)
	}
	guarded = ociclient.WithRequestGuard(ociclient.WithAuthority(guarded, guard), guard)
	if err := guard(ctx); err != nil {
		return verified, err
	}
	body, id, readErr := readOriginalVault(guarded, clients, state)
	if state.Candidate == (originalSourceCandidate{}) {
		if !errors.Is(readErr, os.ErrNotExist) {
			clear(body)
			return verified, ErrMaterialSource
		}
		if err := guard(ctx); err != nil {
			return verified, err
		}
		candidate, err := readOriginalCandidate(dir)
		if errors.Is(err, unix.ENOENT) {
			candidate, err = generateOriginalCandidate(directory, in, state)
			if err == nil {
				err = persistOriginalCandidate(directory, dir, candidate)
			}
		}
		if err != nil {
			clear(candidate)
			return verified, err
		}
		defer clear(candidate)
		archive, _, err := decodeOriginalCandidate(directory, in, state, candidate)
		clearArchive(archive)
		if err != nil {
			return verified, err
		}
		requestSHA, err := originalCreateSHA(state, candidate)
		if err != nil {
			return verified, err
		}
		next := state
		next.Candidate = originalSourceCandidate{SHA256: digestWire(candidate), MaxBytes: int64(len(candidate)), CreateSHA256: requestSHA}
		etag, err = writeOriginalState(guarded, actorCtx, clients.objects, in, next, etag)
		if err != nil {
			return verified, err
		}
		state = next
	}
	if errors.Is(readErr, os.ErrNotExist) {
		if state.Reference != (materialSourceReference{}) || time.Now().Before(state.StartedAt) || !time.Now().Before(state.StartedAt.Add(23*time.Hour)) {
			return verified, ErrMaterialSource
		}
		candidate, err := readOriginalCandidate(dir)
		if err != nil {
			return verified, ErrMaterialSource
		}
		defer clear(candidate)
		archive, _, err := decodeOriginalCandidate(directory, in, state, candidate)
		clearArchive(archive)
		if err != nil {
			return verified, err
		}
		requestSHA, err := originalCreateSHA(state, candidate)
		if err != nil || digestWire(candidate) != state.Candidate.SHA256 || int64(len(candidate)) != state.Candidate.MaxBytes || requestSHA != state.Candidate.CreateSHA256 {
			return verified, ErrMaterialSource
		}
		if err := guard(ctx); err != nil {
			return verified, err
		}
		request := originalCreateRequest(state, candidate)
		createCtx, cancel := context.WithTimeout(guarded, 10*time.Second)
		_, _ = clients.management.CreateSecret(ociclient.RequestContext(createCtx), request)
		cancel()
		body, id, readErr = readOriginalVault(guarded, clients, state)
	}
	if readErr != nil {
		clear(body)
		return verified, readErr
	}
	defer clear(body)
	archive, record, err := decodeOriginalCandidate(directory, in, state, body)
	if err != nil {
		return verified, err
	}
	defer clearArchive(archive)
	if state.Reference == (materialSourceReference{}) {
		next := state
		next.Reference = materialSourceReference{SecretOCID: id, SHA256: digestWire(body), MaxBytes: int64(len(body))}
		etag, err = writeOriginalState(guarded, actorCtx, clients.objects, in, next, etag)
		if err != nil {
			return verified, err
		}
		state = next
	}
	inventory, err := originalInventory(in, state, archive, record)
	if err != nil {
		return verified, err
	}
	if len(state.OriginalAdmissionInventory) == 0 {
		next := state
		next.OriginalAdmissionInventory = inventory
		etag, err = writeOriginalState(guarded, actorCtx, clients.objects, in, next, etag)
		if err != nil {
			return verified, err
		}
		state = next
	}
	verified = VerifiedOriginalSourceArchive{actor: actor, inputs: in, state: state, etag: etag, directory: directory}
	if err := verified.VerifyCurrent(ctx); err != nil {
		return VerifiedOriginalSourceArchive{}, err
	}
	return verified, nil
}

func (v VerifiedOriginalSourceArchive) VerifyCurrent(ctx context.Context) error {
	if ctx == nil || !v.IsVerified() || v.actor.Guard(ctx) != nil {
		return ErrMaterialSource
	}
	clients, guarded, err := originalClients(ctx, v.actor)
	if err != nil {
		return err
	}
	state, etag, err := readOriginalState(guarded, clients.objects, v.inputs)
	if err != nil || etag != v.etag || !sameOriginalState(state, v.state) {
		return ErrMaterialSource
	}
	body, _, err := readOriginalVault(guarded, clients, state)
	if err != nil {
		return err
	}
	defer clear(body)
	archive, record, err := decodeOriginalCandidate(v.directory, v.inputs, state, body)
	if err != nil {
		return err
	}
	defer clearArchive(archive)
	if _, err := originalInventory(v.inputs, state, archive, record); err != nil {
		return err
	}
	current, observed, err := readOriginalState(guarded, clients.objects, v.inputs)
	if err != nil || observed != v.etag || !sameOriginalState(current, v.state) {
		return ErrMaterialSource
	}
	return v.actor.Guard(ctx)
}
