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
	"os"
	"path/filepath"
	"strings"
	"time"
	"uuid"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
	"golang.org/x/sys/unix"
)

const originalStartupLinkKind = "original-startup-link/v1"

type originalStartupLinkState struct {
	SchemaVersion  int                             `json:"schemaVersion"`
	Kind           string                          `json:"kind"`
	InstallationID string                          `json:"installationId"`
	Generation     uint64                          `json:"generation"`
	Cell           string                          `json:"cell"`
	GrantSHA256    string                          `json:"grantSha256"`
	BindingSHA256  string                          `json:"bindingSha256"`
	RegionalSource bootstrap.OriginalSourceBinding `json:"regionalSource"`
	HomeSource     bootstrap.OriginalSourceBinding `json:"homeSource"`
	HomeLinkSHA256 string                          `json:"homeLinkSha256,omitempty"`
	Target         bootstrapmaterial.VaultTarget   `json:"target"`
	SecretName     string                          `json:"secretName"`
	RetryToken     string                          `json:"retryToken"`
	StartedAt      time.Time                       `json:"startedAt"`
	Candidate      originalSourceCandidate         `json:"candidate"`
	Reference      materialSourceReference         `json:"reference"`
	Journal        []byte                          `json:"journal,omitempty"`
	Publication    *bootstrapmaterial.Publication  `json:"publication,omitempty"`
	Delivery       []byte                          `json:"delivery,omitempty"`
}

type originalStartupLinkSource struct {
	owner                *VerifiedOriginalSourceArchive
	template             bootstrap.VerifiedStartupTemplate
	recipient            bootstrap.LinkRecipient
	homeActor            bootstrap.SourceInventoryActor
	clients              originalSourceClients
	state                originalStartupLinkState
	etag, key, directory string
	actorCtx             context.Context
	baseGuard            func(context.Context) error
	publicationScope     region.OriginalMaterialPublicationScope
	factory              *ociclient.Factory
}

func originalLinkLocator(template bootstrap.VerifiedStartupTemplate) (string, string, error) {
	domain, _, err := bootstrap.OriginalSourceObject(template)
	if err != nil {
		return "", "", err
	}
	return bootstrap.OriginalStartupLinkLocator(domain, template.InstallationID(), template.StartupIdentity().Cell)
}

func originalLinkStateWire(state originalStartupLinkState) []byte {
	wire, _ := json.Marshal(state, json.Deterministic(true))
	return wire
}

func originalLinkReservation(state originalStartupLinkState) string {
	state.Candidate, state.Reference = originalSourceCandidate{}, materialSourceReference{}
	state.Journal, state.Publication, state.Delivery = nil, nil, nil
	return digestWire(originalLinkStateWire(state))
}

func originalLinkJournalValid(state originalStartupLinkState, target bootstrapmaterial.VaultTarget, cfg bootstrapmaterial.Config) bool {
	expectedNames, err := bootstrapmaterial.OriginalLinkPublicationSecretNames(cfg)
	if err != nil {
		return false
	}
	if len(state.Journal) == 0 {
		return state.Publication == nil && len(state.Delivery) == 0
	}
	var journal originalPublicationJournal
	if len(state.Journal) > 1<<20 || json.Unmarshal(state.Journal, &journal, json.RejectUnknownMembers(true)) != nil || journal.SchemaVersion != 1 || journal.Target != target || !validDigest(journal.MaterialSHA256) || len(journal.Entries) != 8 {
		return false
	}
	names, files, ids := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i, entry := range journal.Entries {
		if entry.Name != expectedNames[i] || names[entry.Name] || filepath.Base(entry.FileName) != entry.FileName || entry.FileName == "issuer-link.seed" || files[entry.FileName] || i > 0 && journal.Entries[i-1].FileName >= entry.FileName {
			return false
		}
		token, err := uuid.Parse(entry.RetryToken)
		if err != nil || token.String() != entry.RetryToken || entry.Verified != (entry.SecretOCID != "") || entry.Verified && entry.SentAt.IsZero() || !entry.SentAt.IsZero() && (entry.SentAt.Before(state.StartedAt) || entry.SentAt.After(time.Now())) || entry.SecretOCID != "" && (!originalRegionalSecret(entry.SecretOCID, cfg.Region) || ids[entry.SecretOCID]) {
			return false
		}
		names[entry.Name], files[entry.FileName] = true, true
		if entry.SecretOCID != "" {
			ids[entry.SecretOCID] = true
		}
	}
	if state.Publication == nil {
		return len(state.Delivery) == 0
	}
	publication := state.Publication
	if publication.SchemaVersion != 1 || publication.Target != target || publication.MaterialSHA256 != journal.MaterialSHA256 || len(publication.References) != len(journal.Entries) {
		return false
	}
	for i, ref := range publication.References {
		entry := journal.Entries[i]
		r := ref.Reference
		if !entry.Verified || ref.SecretName != entry.Name || r.SecretOCID != entry.SecretOCID || r.TargetFile != entry.FileName || r.VersionNumber != 1 || !validDigest(r.SHA256) || r.MaxBytes <= 0 || r.MaxBytes > bootstrap.MaxSecretBytes || r.Purpose == "owner-only" {
			return false
		}
	}
	return len(state.Delivery) <= 64<<10
}

func immutableOriginalLink(prior, next originalStartupLinkState) bool {
	if originalLinkReservation(prior) != originalLinkReservation(next) || prior.Candidate != (originalSourceCandidate{}) && prior.Candidate != next.Candidate || prior.Reference != (materialSourceReference{}) && prior.Reference != next.Reference || next.Reference != (materialSourceReference{}) && prior.Candidate == (originalSourceCandidate{}) {
		return false
	}
	if len(prior.Journal) == 0 {
		if len(next.Journal) != 0 {
			if prior.Reference == (materialSourceReference{}) || next.Publication != nil {
				return false
			}
			var journal originalPublicationJournal
			if json.Unmarshal(next.Journal, &journal) != nil {
				return false
			}
			for _, entry := range journal.Entries {
				if !entry.SentAt.IsZero() || entry.Verified || entry.SecretOCID != "" {
					return false
				}
			}
		}
	} else {
		// The same monotone journal rules apply to original material and Link leaves.
		a := originalSourceState{Publication: &originalMaterialPublicationState{Journal: prior.Journal, Result: prior.Publication}}
		b := originalSourceState{Publication: &originalMaterialPublicationState{Journal: next.Journal, Result: next.Publication}}
		if !immutableOriginalPublication(a, b) {
			return false
		}
	}
	if len(prior.Delivery) != 0 {
		return bytes.Equal(prior.Delivery, next.Delivery)
	}
	return len(next.Delivery) == 0 || prior.Publication != nil
}

func (link *originalStartupLinkSource) valid(state originalStartupLinkState) bool {
	expected := link.state
	a, b := state, expected
	a.RetryToken, b.RetryToken = "", ""
	a.StartedAt, b.StartedAt = time.Time{}, time.Time{}
	if originalLinkReservation(a) != originalLinkReservation(b) || state.SchemaVersion != 3 || state.Kind != originalStartupLinkKind || state.StartedAt.IsZero() || state.StartedAt.After(time.Now()) || !state.StartedAt.Before(link.recipient.ExpiresAt()) {
		return false
	}
	token, err := uuid.Parse(state.RetryToken)
	if err != nil || token.String() != state.RetryToken {
		return false
	}
	c, r := state.Candidate, state.Reference
	if c == (originalSourceCandidate{}) {
		return r == (materialSourceReference{}) && len(state.Journal) == 0 && state.Publication == nil && len(state.Delivery) == 0
	}
	if !validDigest(c.SHA256) || !validDigest(c.CreateSHA256) || c.MaxBytes <= 0 || c.MaxBytes > materialSourceSecretLimit {
		return false
	}
	if r == (materialSourceReference{}) {
		return len(state.Journal) == 0 && state.Publication == nil && len(state.Delivery) == 0
	}
	target := link.recipient.VaultTarget()
	var record bootstrapmaterial.Record
	if json.Unmarshal(link.recipient.MaterialRecord(), &record, json.RejectUnknownMembers(true)) != nil {
		return false
	}
	return originalSecretID(r.SecretOCID) && r.SHA256 == c.SHA256 && r.MaxBytes == c.MaxBytes && originalLinkJournalValid(state, bootstrapmaterial.VaultTarget{CompartmentOCID: target.CompartmentOCID, VaultOCID: target.VaultOCID, KMSKeyOCID: target.KMSKeyOCID}, record.Config)
}

func (link *originalStartupLinkSource) read(ctx context.Context) (originalStartupLinkState, string, error) {
	var state originalStartupLinkState
	domain := link.recipient.StorageDomain()
	policy := common.NoRetryPolicy()
	response, err := link.clients.objects.GetObject(ociclient.RequestContext(ctx), objectstorage.GetObjectRequest{NamespaceName: new(domain.Namespace), BucketName: new(domain.HeadBucket), ObjectName: new(link.key), RequestMetadata: common.RequestMetadata{RetryPolicy: &policy}})
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
	wire, err := io.ReadAll(io.LimitReader(response.Content, originalSourceStateLimit+1))
	etag := derefOriginal(response.ETag)
	if err != nil || len(wire) > originalSourceStateLimit || etag == "" || len(etag) > 1024 || strings.ContainsAny(etag, "\x00\r\n") || json.Unmarshal(wire, &state, json.RejectUnknownMembers(true)) != nil || !link.valid(state) || !bytes.Equal(wire, originalLinkStateWire(state)) {
		return originalStartupLinkState{}, "", ErrMaterialSource
	}
	return state, etag, nil
}

func (link *originalStartupLinkSource) base(dispatch context.Context) error {
	check := originalPublicationCheckpointContext(dispatch, link.actorCtx)
	if err := link.baseGuard(check); err != nil {
		return err
	}
	scope, _, _, err := link.owner.actor.OriginalLinkPublication(check, link.template.StartupIdentity().Cell)
	if err != nil || scope != link.publicationScope {
		return errors.Join(ErrMaterialSource, err)
	}
	return link.recipient.VerifyCurrent(check, time.Now())
}

func (link *originalStartupLinkSource) guard(dispatch context.Context) error {
	if err := dispatch.Err(); err != nil {
		return err
	}
	if err := link.base(dispatch); err != nil {
		return err
	}
	check := originalPublicationCheckpointContext(dispatch, link.actorCtx)
	current, etag, err := link.read(check)
	if err != nil || etag != link.etag || !bytes.Equal(originalLinkStateWire(current), originalLinkStateWire(link.state)) {
		return errors.Join(ErrMaterialSource, err)
	}
	return ociclient.LimitAdmission(dispatch, link.recipient.ExpiresAt())
}

func (link *originalStartupLinkSource) write(ctx context.Context, next originalStartupLinkState) error {
	if !link.valid(next) {
		return ErrMaterialSource
	}
	if link.etag == "" {
		if next.Candidate != (originalSourceCandidate{}) || next.Reference != (materialSourceReference{}) || len(next.Journal) != 0 {
			return ErrMaterialSource
		}
		if err := link.base(ctx); err != nil {
			return err
		}
	} else {
		if err := link.guard(ctx); err != nil {
			return err
		}
		if !immutableOriginalLink(link.state, next) {
			return ErrMaterialSource
		}
	}
	wire := originalLinkStateWire(next)
	if len(wire) > originalSourceStateLimit {
		return ErrMaterialSource
	}
	domain := link.recipient.StorageDomain()
	policy := common.NoRetryPolicy()
	request := objectstorage.PutObjectRequest{NamespaceName: new(domain.Namespace), BucketName: new(domain.HeadBucket), ObjectName: new(link.key), OpcSseKmsKeyId: new(domain.HeadKMSKeyOCID), ContentLength: new(int64(len(wire))), PutObjectBody: io.NopCloser(bytes.NewReader(wire)), RequestMetadata: common.RequestMetadata{RetryPolicy: &policy}}
	if link.etag == "" {
		request.IfNoneMatch = new("*")
	} else {
		request.IfMatch = new(link.etag)
	}
	dispatch, cancel := context.WithTimeout(ctx, 10*time.Second)
	_, _ = link.clients.objects.PutObject(ociclient.RequestContext(dispatch), request)
	cancel()
	// Preserve source, recipient and caller guards while dropping the old Link CAS.
	if err := link.base(ctx); err != nil {
		return err
	}
	check := originalPublicationCheckpointContext(ctx, link.actorCtx)
	current, etag, err := link.read(check)
	if err != nil || !bytes.Equal(originalLinkStateWire(current), wire) {
		return errors.Join(ErrMaterialSource, err)
	}
	link.state, link.etag = current, etag
	return nil
}

func originalSourceBinding(ctx context.Context, template bootstrap.VerifiedStartupTemplate, objects bootstrap.ObjectStorageClient) (bootstrap.OriginalSourceBinding, error) {
	domain, key, err := bootstrap.OriginalSourceObject(template)
	if err != nil {
		return bootstrap.OriginalSourceBinding{}, err
	}
	response, err := objects.GetObject(ociclient.RequestContext(ctx), objectstorage.GetObjectRequest{NamespaceName: new(domain.Namespace), BucketName: new(domain.HeadBucket), ObjectName: new(key)})
	if err != nil {
		return bootstrap.OriginalSourceBinding{}, err
	}
	if response.Content == nil {
		return bootstrap.OriginalSourceBinding{}, ErrMaterialSource
	}
	defer response.Content.Close()
	wire, err := io.ReadAll(io.LimitReader(response.Content, originalSourceStateLimit+1))
	if err != nil || len(wire) > originalSourceStateLimit {
		return bootstrap.OriginalSourceBinding{}, ErrMaterialSource
	}
	return bootstrap.OriginalSourceBindingFor(wire)
}

func (v *VerifiedOriginalSourceArchive) newOriginalLink(ctx context.Context, template bootstrap.VerifiedStartupTemplate, recipient bootstrap.LinkRecipient, homeLinkSHA, directory string, now time.Time) (*originalStartupLinkSource, error) {
	clients, actorCtx, _, guard, err := v.originalStartupSession(ctx, template)
	if err != nil {
		return nil, err
	}
	home, err := template.ForCell(ctx, oci.RegionGRU, now)
	if err != nil {
		return nil, err
	}
	regionalBinding, err := originalSourceBinding(ctx, template, clients.objects)
	if err != nil {
		return nil, err
	}
	homeBinding, err := originalSourceBinding(ctx, home, clients.objects)
	if err != nil {
		return nil, err
	}
	homeProof, err := bootstrap.LoadRegionalSource(ctx, home, clients.objects, now)
	if err != nil {
		return nil, err
	}
	key, name, err := originalLinkLocator(template)
	if err != nil {
		return nil, err
	}
	bindingWire, err := json.Marshal([]string{originalStartupLinkKind, template.InstallationID(), strings.ToLower(string(template.StartupIdentity().Cell)), template.GrantDigest(), regionalBinding.StateSHA256, homeBinding.StateSHA256}, json.Deterministic(true))
	if err != nil || digestWire(bindingWire) != recipient.BindingSHA256() {
		return nil, errors.Join(ErrMaterialSource, err)
	}
	state := originalStartupLinkState{SchemaVersion: 3, Kind: originalStartupLinkKind, InstallationID: template.InstallationID(), Generation: template.Generation(), Cell: strings.ToLower(string(template.StartupIdentity().Cell)), GrantSHA256: template.GrantDigest(), BindingSHA256: recipient.BindingSHA256(), RegionalSource: regionalBinding, HomeSource: homeBinding, HomeLinkSHA256: homeLinkSHA, Target: v.inputs.intent.Escrow, SecretName: name, RetryToken: uuid.New().String(), StartedAt: now.UTC()}
	scope, factory, materialCtx, err := v.actor.OriginalLinkPublication(ctx, template.StartupIdentity().Cell)
	if err != nil {
		return nil, err
	}
	var record bootstrapmaterial.Record
	if json.Unmarshal(recipient.MaterialRecord(), &record, json.RejectUnknownMembers(true)) != nil {
		return nil, ErrMaterialSource
	}
	names, err := bootstrapmaterial.OriginalLinkPublicationSecretNames(record.Config)
	if err != nil {
		return nil, err
	}
	target := recipient.VaultTarget()
	if key != recipient.LinkObjectKey() || scope.OriginalLinkObject != key || scope.OriginalLinkSecretName != name || scope.OriginalLinkEscrow != state.Target || scope.SecretNames != names || scope.Target != (bootstrapmaterial.VaultTarget{CompartmentOCID: target.CompartmentOCID, VaultOCID: target.VaultOCID, KMSKeyOCID: target.KMSKeyOCID}) {
		return nil, ErrMaterialSource
	}
	actorCtx = originalPublicationContext{Context: actorCtx, values: materialCtx}
	return &originalStartupLinkSource{owner: v, template: template, recipient: recipient, homeActor: homeProof.OriginalActor(), clients: clients, state: state, key: key, directory: directory, actorCtx: actorCtx, baseGuard: guard, publicationScope: scope, factory: factory}, nil
}

func originalLinkArchive(directory string, state originalStartupLinkState, template bootstrap.VerifiedStartupTemplate) ([]byte, error) {
	record, err := bootstrapmaterial.LoadLink(directory, time.Now())
	if err != nil {
		return nil, err
	}
	archive := materialSourceArchive{SchemaVersion: 3, Kind: originalStartupLinkKind, BindingSHA256: originalLinkReservation(state), InstallationID: state.InstallationID, Cell: state.Cell, Generation: state.Generation, PlanSHA256: template.PlanDigest(), Files: map[string][]byte{}}
	defer clearArchive(archive)
	names := []string{"material.json", "READY"}
	for _, file := range record.Files {
		names = append(names, file.Name)
	}
	for _, name := range names {
		archive.Files[name], err = os.ReadFile(filepath.Join(directory, name))
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
	if compressed.Len() > materialSourceSecretLimit {
		return nil, ErrMaterialSource
	}
	return compressed.Bytes(), nil
}

func (link *originalStartupLinkSource) restore(body []byte, directory string, now time.Time) (bootstrapmaterial.LinkRecord, error) {
	reader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return bootstrapmaterial.LinkRecord{}, err
	}
	defer reader.Close()
	wire, err := io.ReadAll(io.LimitReader(reader, materialSourceLimit+1))
	defer clear(wire)
	var archive materialSourceArchive
	if err != nil || len(wire) > materialSourceLimit || json.Unmarshal(wire, &archive, json.RejectUnknownMembers(true)) != nil {
		return bootstrapmaterial.LinkRecord{}, ErrMaterialSource
	}
	defer clearArchive(archive)
	if archive.SchemaVersion != 3 || archive.Kind != originalStartupLinkKind || archive.BindingSHA256 != originalLinkReservation(link.state) || archive.InstallationID != link.state.InstallationID || archive.Cell != link.state.Cell || archive.Generation != link.state.Generation || archive.PlanSHA256 != link.template.PlanDigest() {
		return bootstrapmaterial.LinkRecord{}, ErrMaterialSource
	}
	if err := restoreOriginalFiles(directory, archive.Files); err != nil {
		return bootstrapmaterial.LinkRecord{}, err
	}
	record, err := bootstrapmaterial.LoadLink(directory, now)
	cfg, encodeErr := json.Marshal(record.Config, json.Deterministic(true))
	if err != nil || encodeErr != nil || digestWire(cfg) != link.template.PlanDigest() || record.SourceSHA256 != link.recipient.SourceSHA256() || record.HomeSHA256 != link.recipient.HomeSHA256() || record.HomeLinkSHA256 != link.state.HomeLinkSHA256 {
		return bootstrapmaterial.LinkRecord{}, ErrMaterialSource
	}
	var recipient bootstrapmaterial.Record
	if json.Unmarshal(link.recipient.MaterialRecord(), &recipient, json.RejectUnknownMembers(true)) != nil || record.Public != recipient.Public {
		return bootstrapmaterial.LinkRecord{}, ErrMaterialSource
	}
	allowed := map[string]bool{"material.json": true, "READY": true}
	for _, file := range record.Files {
		allowed[file.Name] = true
	}
	if len(archive.Files) != len(allowed) {
		return bootstrapmaterial.LinkRecord{}, ErrMaterialSource
	}
	for name := range archive.Files {
		if !allowed[name] {
			return bootstrapmaterial.LinkRecord{}, ErrMaterialSource
		}
	}
	return record, nil
}

func restoreOriginalFiles(directory string, files map[string][]byte) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return ErrMaterialSource
	}
	validate := func() error {
		fd, err := openSourceDirectory(directory)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		for name, expected := range files {
			if filepath.Base(name) != name || name == "." || len(expected) == 0 {
				return ErrMaterialSource
			}
			var stat unix.Stat_t
			if err := unix.Fstatat(fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 {
				return ErrMaterialSource
			}
			actual, err := os.ReadFile(filepath.Join(directory, name))
			same := err == nil && bytes.Equal(actual, expected)
			clear(actual)
			if !same {
				return ErrMaterialSource
			}
		}
		return nil
	}
	if _, err := os.Lstat(directory); err == nil {
		return validate()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	staging, err := os.MkdirTemp(filepath.Dir(directory), ".original-restore-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	for name, body := range files {
		if filepath.Base(name) != name || name == "." || len(body) == 0 {
			return ErrMaterialSource
		}
		if err := writeSourceFile(filepath.Join(staging, name), body); err != nil {
			return err
		}
	}
	if err := syncSourceDirectory(staging); err != nil {
		return err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, staging, unix.AT_FDCWD, directory, unix.RENAME_NOREPLACE); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	if err := syncSourceDirectory(filepath.Dir(directory)); err != nil {
		return err
	}
	return validate()
}

// readEscrow uses the immutable Link policy's ID-based bundle operation.
func (link *originalStartupLinkSource) readEscrow(ctx context.Context) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	state := link.state
	target, name := state.Target, state.SecretName
	policy := common.NoRetryPolicy()
	id := state.Reference.SecretOCID
	if state.Reference != (materialSourceReference{}) && !originalSecretID(id) {
		return nil, "", ErrMaterialSource
	}
	if id == "" {
		var page *string
		pages := map[string]bool{}
		complete := false
		for range 32 {
			response, err := link.clients.management.ListSecrets(ociclient.RequestContext(ctx), ocivault.ListSecretsRequest{
				CompartmentId: new(target.CompartmentOCID), VaultId: new(target.VaultOCID), Name: new(name), Page: page,
				RequestMetadata: common.RequestMetadata{RetryPolicy: &policy},
			})
			if err != nil {
				return nil, "", err
			}
			for _, item := range response.Items {
				if id != "" || !originalSecretID(derefOriginal(item.Id)) || derefOriginal(item.SecretName) != name ||
					derefOriginal(item.CompartmentId) != target.CompartmentOCID || derefOriginal(item.VaultId) != target.VaultOCID ||
					item.LifecycleState != ocivault.SecretSummaryLifecycleStateActive && item.LifecycleState != ocivault.SecretSummaryLifecycleStateCreating {
					return nil, "", ErrMaterialSource
				}
				id = *item.Id
			}
			if response.OpcNextPage == nil {
				complete = true
				break
			}
			next := *response.OpcNextPage
			if next == "" || len(next) > 1024 || strings.ContainsAny(next, "\x00\r\n") || pages[next] {
				return nil, "", ErrMaterialSource
			}
			pages[next] = true
			page = response.OpcNextPage
		}
		if !complete {
			return nil, "", ErrMaterialSource
		}
		if id == "" {
			return nil, "", os.ErrNotExist
		}
	}
	secret, err := link.clients.management.GetSecret(ociclient.RequestContext(ctx), ocivault.GetSecretRequest{
		SecretId: new(id), RequestMetadata: common.RequestMetadata{RetryPolicy: &policy},
	})
	if err != nil || derefOriginal(secret.Id) != id || derefOriginal(secret.CompartmentId) != target.CompartmentOCID ||
		derefOriginal(secret.VaultId) != target.VaultOCID || derefOriginal(secret.KeyId) != target.KMSKeyOCID ||
		derefOriginal(secret.SecretName) != name || secret.LifecycleState != ocivault.SecretLifecycleStateActive ||
		secret.CurrentVersionNumber == nil || *secret.CurrentVersionNumber != 1 {
		return nil, "", errors.Join(ErrMaterialSource, err)
	}
	response, err := link.clients.bundles.GetSecretBundle(ociclient.RequestContext(ctx), ocisecrets.GetSecretBundleRequest{
		SecretId: new(id), VersionNumber: new(int64(1)), RequestMetadata: common.RequestMetadata{RetryPolicy: &policy},
	})
	if err != nil || derefOriginal(response.SecretId) != id || response.VersionNumber == nil || *response.VersionNumber != 1 {
		return nil, "", errors.Join(ErrMaterialSource, err)
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
	candidate := state.Candidate
	if candidate == (originalSourceCandidate{}) || digestWire(body) != candidate.SHA256 || int64(len(body)) != candidate.MaxBytes ||
		state.Reference != (materialSourceReference{}) && state.Reference != (materialSourceReference{SecretOCID: id, SHA256: digestWire(body), MaxBytes: int64(len(body))}) {
		clear(body)
		return nil, "", ErrMaterialSource
	}
	requestSHA, err := originalEscrowSHA(target, name, state.RetryToken, body)
	if err != nil || requestSHA != candidate.CreateSHA256 {
		clear(body)
		return nil, "", ErrMaterialSource
	}
	return body, id, nil
}

func (link *originalStartupLinkSource) issue(ctx context.Context, homeDirectory, homeLinkDirectory string, ledger ed25519.PrivateKey, now time.Time) (bootstrap.VerifiedStartupLink, error) {
	deny := func() (bootstrap.VerifiedStartupLink, error) {
		return bootstrap.VerifiedStartupLink{}, ErrMaterialSource
	}
	dir, unlock, err := lockOriginalDirectory(link.directory)
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	defer unlock()
	state, etag, err := link.read(ctx)
	if errors.Is(err, os.ErrNotExist) {
		err = link.write(ctx, link.state)
	} else if err == nil {
		link.state, link.etag = state, etag
	}
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	guarded := ociclient.WithRequestGuard(ociclient.WithAuthority(link.actorCtx, link.guard), link.guard)
	materialDirectory := filepath.Join(link.directory, "material")
	body, id, readErr := link.readEscrow(guarded)
	if link.state.Candidate == (originalSourceCandidate{}) {
		if !errors.Is(readErr, os.ErrNotExist) {
			clear(body)
			return deny()
		}
		candidate, err := readOriginalCandidate(dir)
		if errors.Is(err, unix.ENOENT) {
			if err = link.guard(ctx); err != nil {
				return bootstrap.VerifiedStartupLink{}, err
			}
			if link.state.Cell == "gru" {
				_, err = bootstrapmaterial.GenerateOriginalLink(guarded, link.template, homeDirectory, homeDirectory, materialDirectory, materialDirectory, now)
			} else {
				var recipient bootstrapmaterial.Record
				if json.Unmarshal(link.recipient.MaterialRecord(), &recipient, json.RejectUnknownMembers(true)) != nil {
					return deny()
				}
				_, err = bootstrapmaterial.GenerateOriginalSpokeLink(guarded, link.template, homeDirectory, homeLinkDirectory, recipient, link.recipient.SourceSHA256(), materialDirectory, now)
			}
			if err == nil {
				candidate, err = originalLinkArchive(materialDirectory, link.state, link.template)
			}
			if err == nil {
				err = persistOriginalCandidate(link.directory, dir, candidate)
			}
		}
		if err != nil {
			clear(candidate)
			return bootstrap.VerifiedStartupLink{}, err
		}
		defer clear(candidate)
		if _, err := link.restore(candidate, materialDirectory, now); err != nil {
			return bootstrap.VerifiedStartupLink{}, err
		}
		requestSHA, err := originalEscrowSHA(link.state.Target, link.state.SecretName, link.state.RetryToken, candidate)
		if err != nil {
			return bootstrap.VerifiedStartupLink{}, err
		}
		next := link.state
		next.Candidate = originalSourceCandidate{SHA256: digestWire(candidate), MaxBytes: int64(len(candidate)), CreateSHA256: requestSHA}
		if err := link.write(guarded, next); err != nil {
			return bootstrap.VerifiedStartupLink{}, err
		}
	}
	if errors.Is(readErr, os.ErrNotExist) {
		if link.state.Reference != (materialSourceReference{}) || !time.Now().Before(link.state.StartedAt.Add(23*time.Hour)) {
			return deny()
		}
		candidate, err := readOriginalCandidate(dir)
		if err != nil {
			return bootstrap.VerifiedStartupLink{}, err
		}
		defer clear(candidate)
		requestSHA, err := originalEscrowSHA(link.state.Target, link.state.SecretName, link.state.RetryToken, candidate)
		if err != nil || digestWire(candidate) != link.state.Candidate.SHA256 || int64(len(candidate)) != link.state.Candidate.MaxBytes || requestSHA != link.state.Candidate.CreateSHA256 {
			return deny()
		}
		if _, err := link.restore(candidate, materialDirectory, now); err != nil {
			return bootstrap.VerifiedStartupLink{}, err
		}
		dispatch, cancel := context.WithTimeout(guarded, 10*time.Second)
		_, _ = link.clients.management.CreateSecret(ociclient.RequestContext(dispatch), originalEscrowRequest(link.state.Target, link.state.SecretName, link.state.RetryToken, candidate))
		cancel()
		body, id, readErr = link.readEscrow(guarded)
	}
	if readErr != nil {
		clear(body)
		return bootstrap.VerifiedStartupLink{}, readErr
	}
	defer clear(body)
	record, err := link.restore(body, materialDirectory, now)
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	homeRecord, err := bootstrapmaterial.Load(homeDirectory)
	if err != nil || record.HomeAccount != homeRecord.Public.CellAccountNKey {
		return deny()
	}
	if link.state.Cell != "gru" {
		homeLink, err := bootstrapmaterial.LoadLink(homeLinkDirectory, now)
		if err != nil || record.Signer != homeLink.Signer {
			return deny()
		}
	}
	if link.state.Reference == (materialSourceReference{}) {
		next := link.state
		next.Reference = materialSourceReference{SecretOCID: id, SHA256: digestWire(body), MaxBytes: int64(len(body))}
		if err := link.write(guarded, next); err != nil {
			return bootstrap.VerifiedStartupLink{}, err
		}
	}
	if err := link.restoreJournal(guarded, materialDirectory); err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}

	regional, err := link.factory.ForRegion(record.Config.Region)
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	management, bundles, err := linkVaultClients(regional)
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	target := link.recipient.VaultTarget()
	guarded = bootstrapmaterial.WithPublicationGuard(guarded, link.guard)
	publication, err := bootstrapmaterial.ProvisionLinkDurable(guarded, materialDirectory, bootstrapmaterial.VaultTarget{CompartmentOCID: target.CompartmentOCID, VaultOCID: target.VaultOCID, KMSKeyOCID: target.KMSKeyOCID}, management, bundles, now, func(journal []byte) error {
		if bytes.Equal(link.state.Journal, journal) {
			return link.guard(ctx)
		}
		next := link.state
		next.Journal = bytes.Clone(journal)
		return link.write(guarded, next)
	})
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	if err := bootstrapmaterial.ValidateLinkPublication(materialDirectory, publication, link.state.Journal, now); err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	if link.state.Publication == nil {
		next := link.state
		next.Publication = new(publication)
		if err := link.write(guarded, next); err != nil {
			return bootstrap.VerifiedStartupLink{}, err
		}
	} else {
		a, _ := json.Marshal(link.state.Publication, json.Deterministic(true))
		b, _ := json.Marshal(publication, json.Deterministic(true))
		if !bytes.Equal(a, b) {
			return deny()
		}
	}
	metadata, err := os.ReadFile(filepath.Join(materialDirectory, "material.json"))
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	evidence := bootstrap.RegionalLinkEvidence{Actor: link.homeActor, SourceObjectKey: link.key, SourceSHA256: link.state.Reference.SHA256, MaterialRecord: metadata, Journal: bytes.Clone(link.state.Journal), References: publication.LinkGenerationReferences()}
	payload, err := bootstrap.LinkDeliveryPayload(evidence)
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	if len(link.state.Delivery) == 0 {
		next := link.state
		next.Delivery, err = bootstrap.SignLinkDelivery(link.recipient, payload, ledger, link.state.StartedAt, minOriginalTime(link.recipient.ExpiresAt(), record.ExpiresAt))
		if err != nil {
			return bootstrap.VerifiedStartupLink{}, err
		}
		if err := link.write(guarded, next); err != nil {
			return bootstrap.VerifiedStartupLink{}, err
		}
	} else {
		prior, err := bootstrap.VerifyLinkDelivery(ctx, link.recipient, link.state.Delivery, now)
		if err != nil || !bytes.Equal(prior, payload) {
			return deny()
		}
	}
	evidence.Delivery = bytes.Clone(link.state.Delivery)
	if err := link.guard(ctx); err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	return bootstrap.VerifyStartupLink(guarded, link.template, link.clients.objects, evidence, now)
}

func (v *VerifiedOriginalSourceArchive) originalStartupLink(ctx context.Context, template bootstrap.VerifiedStartupTemplate, now time.Time) (bootstrap.VerifiedStartupLink, error) {
	clients, _, guarded, guard, err := v.originalStartupSession(ctx, template)
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	homeTemplate, err := template.ForCell(ctx, oci.RegionGRU, now)
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	homeProof, err := bootstrap.LoadRegionalSource(guarded, homeTemplate, clients.objects, now)
	if originalLinkSourcePending(err) {
		return bootstrap.VerifiedStartupLink{}, ErrLinkDeliveryPending
	}
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	regionalProof, err := bootstrap.LoadRegionalSource(guarded, template, clients.objects, now)
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	recipient, err := bootstrap.VerifyLinkRecipient(guarded, regionalProof, homeProof, now)
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	if template.StartupIdentity().Cell != oci.RegionGRU {
		return v.readOriginalLink(guarded, template, recipient, clients, now)
	}
	_, unlock, err := lockOriginalDirectory(v.directory)
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	defer unlock()
	body, _, err := readOriginalVault(guarded, clients, v.state)
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	defer clear(body)
	archive, _, err := decodeOriginalCandidate(v.directory, v.inputs, v.state, body)
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	defer clearArchive(archive)
	work := filepath.Join(v.directory, "original-startup-link")
	if err := os.MkdirAll(work, 0o700); err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	homeDirectory := filepath.Join(work, "home-source")
	if err := restoreOriginalFiles(homeDirectory, archive.Files); err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	own, err := v.newOriginalLink(guarded, template, recipient, "", filepath.Join(work, "gru"), now)
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	proof, err := own.issue(guarded, homeDirectory, "", ed25519.PrivateKey(archive.Files["founder-ledger.key"]), now)
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	// Read the roster as DATA, then independently verify every selected template.
	envelope, err := trust.DecodeEnvelope(template.GrantWire())
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	var grant region.FoundationGrant
	if json.Unmarshal(envelope.Payload, &grant, json.RejectUnknownMembers(true)) != nil {
		return bootstrap.VerifiedStartupLink{}, ErrMaterialSource
	}
	homeLinkDirectory := filepath.Join(own.directory, "material")
	metadata, err := os.ReadFile(filepath.Join(homeLinkDirectory, "material.json"))
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	for _, intent := range grant.Regions {
		cell, ok := intent.Plan["cell"].(string)
		if !ok {
			return bootstrap.VerifiedStartupLink{}, ErrMaterialSource
		}
		if oci.Region(cell) == oci.RegionGRU {
			continue
		}
		peer, err := template.ForCell(guarded, oci.Region(cell), now)
		if err != nil {
			return bootstrap.VerifiedStartupLink{}, err
		}
		peerProof, err := bootstrap.LoadRegionalSource(guarded, peer, clients.objects, now)
		if originalLinkSourcePending(err) {
			continue
		}
		if err != nil {
			return bootstrap.VerifiedStartupLink{}, err
		}
		target, err := bootstrap.VerifyLinkRecipient(guarded, peerProof, homeProof, now)
		if err != nil {
			return bootstrap.VerifiedStartupLink{}, err
		}
		spoke, err := v.newOriginalLink(guarded, peer, target, digestWire(metadata), filepath.Join(work, strings.ToLower(cell)), now)
		if err != nil {
			return bootstrap.VerifiedStartupLink{}, err
		}
		if _, err := spoke.issue(guarded, homeDirectory, homeLinkDirectory, ed25519.PrivateKey(archive.Files["founder-ledger.key"]), now); err != nil {
			return bootstrap.VerifiedStartupLink{}, err
		}
	}
	if err := guard(ctx); err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	return proof, nil
}

func (v *VerifiedOriginalSourceArchive) readOriginalLink(ctx context.Context, template bootstrap.VerifiedStartupTemplate, recipient bootstrap.LinkRecipient, clients originalSourceClients, now time.Time) (bootstrap.VerifiedStartupLink, error) {
	// Spokes consume the fixed public object and only their own Vault leaves.
	domain := recipient.StorageDomain()
	response, err := clients.objects.GetObject(ociclient.RequestContext(ctx), objectstorage.GetObjectRequest{NamespaceName: new(domain.Namespace), BucketName: new(domain.HeadBucket), ObjectName: new(recipient.LinkObjectKey())})
	if service, ok := common.IsServiceError(err); ok && service.GetHTTPStatusCode() == 404 {
		return bootstrap.VerifiedStartupLink{}, ErrLinkDeliveryPending
	}
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	if response.Content == nil {
		return bootstrap.VerifiedStartupLink{}, ErrMaterialSource
	}
	defer response.Content.Close()
	wire, err := io.ReadAll(io.LimitReader(response.Content, originalSourceStateLimit+1))
	var state originalStartupLinkState
	if err != nil || len(wire) > originalSourceStateLimit || json.Unmarshal(wire, &state, json.RejectUnknownMembers(true)) != nil {
		return bootstrap.VerifiedStartupLink{}, ErrMaterialSource
	}
	if !bytes.Equal(wire, originalLinkStateWire(state)) || !validDigest(state.HomeLinkSHA256) {
		return bootstrap.VerifiedStartupLink{}, ErrMaterialSource
	}
	domain, _, locatorErr := bootstrap.OriginalSourceObject(template)
	if locatorErr != nil {
		return bootstrap.VerifiedStartupLink{}, locatorErr
	}
	objectKey, name, locatorErr := bootstrap.OriginalStartupLinkLocator(domain, template.InstallationID(), template.StartupIdentity().Cell)
	if locatorErr != nil {
		return bootstrap.VerifiedStartupLink{}, locatorErr
	}
	regionalBinding, err := originalSourceBinding(ctx, template, clients.objects)
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	homeTemplate, err := template.ForCell(ctx, oci.RegionGRU, now)
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	homeBinding, err := originalSourceBinding(ctx, homeTemplate, clients.objects)
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	expectedState := state
	expectedState.SchemaVersion, expectedState.Kind = 3, originalStartupLinkKind
	expectedState.InstallationID, expectedState.Generation = template.InstallationID(), template.Generation()
	expectedState.Cell, expectedState.GrantSHA256 = strings.ToLower(string(template.StartupIdentity().Cell)), template.GrantDigest()
	expectedState.BindingSHA256 = recipient.BindingSHA256()
	expectedState.RegionalSource, expectedState.HomeSource = regionalBinding, homeBinding
	expectedState.SecretName = name
	expectedState.Target = v.inputs.intent.Escrow
	expected := &originalStartupLinkSource{state: expectedState, recipient: recipient, template: template}
	if objectKey != recipient.LinkObjectKey() || !expected.valid(state) {
		return bootstrap.VerifiedStartupLink{}, ErrMaterialSource
	}
	if len(state.Delivery) == 0 {
		return bootstrap.VerifiedStartupLink{}, ErrLinkDeliveryPending
	}
	payload, err := bootstrap.VerifyLinkDelivery(ctx, recipient, state.Delivery, now)
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	var evidence bootstrap.RegionalLinkEvidence
	if json.Unmarshal(payload, &evidence, json.RejectUnknownMembers(true)) != nil {
		return bootstrap.VerifiedStartupLink{}, ErrMaterialSource
	}
	evidence.Delivery = bytes.Clone(state.Delivery)
	proof, err := bootstrap.VerifyStartupLink(ctx, template, clients.objects, evidence, now)
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	var record bootstrapmaterial.LinkRecord
	if json.Unmarshal(evidence.MaterialRecord, &record, json.RejectUnknownMembers(true)) != nil {
		return bootstrap.VerifiedStartupLink{}, ErrMaterialSource
	}
	publication, err := linkPublication(evidence, recipient.VaultTarget())
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	factory, _, err := v.actor.GuardedFactory(ctx)
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	regional, err := factory.ForRegion(record.Config.Region)
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	_, bundles, err := linkVaultClients(regional)
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	directory := filepath.Join(v.directory, "original-startup-regional-link")
	_, _, _, sourceGuard, err := v.originalStartupSession(ctx, template)
	if err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	leafGuard := func(dispatch context.Context) error {
		if err := sourceGuard(dispatch); err != nil {
			return err
		}
		return proof.VerifyCurrent(originalPublicationCheckpointContext(dispatch, ctx), time.Now())
	}
	guarded := ociclient.WithRequestGuard(ociclient.WithAuthority(ctx, leafGuard), leafGuard)
	guarded = bootstrapmaterial.WithPublicationGuard(guarded, leafGuard)
	if err := restoreRegionalLink(guarded, proof, record, publication, bundles, directory, now); err != nil {
		return bootstrap.VerifiedStartupLink{}, err
	}
	return proof, nil
}

func (link *originalStartupLinkSource) restoreJournal(ctx context.Context, directory string) error {
	dir, err := openSourceDirectory(directory)
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
	if err := unix.Flock(lock, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return err
	}
	defer unix.Flock(lock, unix.LOCK_UN)
	if err := link.guard(ctx); err != nil {
		return err
	}
	if len(link.state.Journal) == 0 {
		if err := unix.Unlinkat(dir, "publication.json", 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return err
		}
		return unix.Fsync(dir)
	}
	temporary, err := os.CreateTemp(link.directory, ".restore-link-journal-")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(link.state.Journal); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := link.guard(ctx); err != nil {
		return err
	}
	if err := unix.Renameat(unix.AT_FDCWD, temporary.Name(), dir, "publication.json"); err != nil {
		return err
	}
	return unix.Fsync(dir)
}

func originalLinkSourcePending(err error) bool {
	if errors.Is(err, bootstrap.ErrOriginalSourcePending) || errors.Is(err, os.ErrNotExist) {
		return true
	}
	service, ok := common.IsServiceError(err)
	return ok && service.GetHTTPStatusCode() == 404
}
