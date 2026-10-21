package bootstrapmaterial

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"uuid"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

const (
	journalName     = "publication.json"
	journalTempName = ".publication.tmp"
	journalLockName = "publication.lock"
	retryWindow     = 23 * time.Hour // OCI retry tokens expire after 24 hours.
)

var (
	ErrProvision   = errors.New("controller material Vault publication needs operator inspection")
	compartmentRE  = regexp.MustCompile(`^ocid1\.compartment\.oc1\.\.[a-z0-9]+(?:\.[a-z0-9]+)*$`)
	resourcePartRE = regexp.MustCompile(`^[a-z0-9]+(?:\.[a-z0-9]+)*$`)
)

type VaultTarget struct {
	CompartmentOCID string `json:"compartmentOcid"`
	VaultOCID       string `json:"vaultOcid"`
	KMSKeyOCID      string `json:"kmsKeyOcid"`
}

// supportedMaterialRegion admits exactly the OCI regions of the region
// catalog, so adding a cell there is the only change material publication
// needs.
func supportedMaterialRegion(region string) bool { return catalog.IsOCIRegion(region) }

func regionalResourceOCID(id, kind, region string) bool {
	prefix := "ocid1." + kind + ".oc1." + region + "."
	return strings.HasPrefix(id, prefix) && resourcePartRE.MatchString(strings.TrimPrefix(id, prefix))
}

func (target VaultTarget) validate(region string) error {
	if !supportedMaterialRegion(region) || !compartmentRE.MatchString(target.CompartmentOCID) ||
		!regionalResourceOCID(target.VaultOCID, "vault", region) ||
		!regionalResourceOCID(target.KMSKeyOCID, "key", region) {
		return ErrProvision
	}
	return nil
}

// Validate binds the control-compartment Vault target to a mapped OCI region.
func (target VaultTarget) Validate(region string) error { return target.validate(region) }

type VaultClient interface {
	CreateSecret(context.Context, ocivault.CreateSecretRequest) (ocivault.CreateSecretResponse, error)
	GetSecret(context.Context, ocivault.GetSecretRequest) (ocivault.GetSecretResponse, error)
	ListSecrets(context.Context, ocivault.ListSecretsRequest) (ocivault.ListSecretsResponse, error)
}

type BundleClient interface {
	GetSecretBundle(context.Context, ocisecrets.GetSecretBundleRequest) (ocisecrets.GetSecretBundleResponse, error)
}

type PublicReference struct {
	SecretName string                    `json:"secretName"`
	Reference  bootstrap.SecretReference `json:"reference"`
}

type Publication struct {
	SchemaVersion  int               `json:"schemaVersion"`
	Target         VaultTarget       `json:"target"`
	MaterialSHA256 string            `json:"materialSha256"`
	References     []PublicReference `json:"references"`
}

type journalEntry struct {
	Name       string    `json:"name"`
	FileName   string    `json:"fileName"`
	RetryToken string    `json:"retryToken"`
	SentAt     time.Time `json:"sentAt"`
	SecretOCID string    `json:"secretOcid,omitempty"`
	Verified   bool      `json:"verified"`
}

type journal struct {
	SchemaVersion  int            `json:"schemaVersion"`
	Target         VaultTarget    `json:"target"`
	MaterialSHA256 string         `json:"materialSha256"`
	Entries        []journalEntry `json:"entries"`
}

// Provision resumes one durable source and publishes each file once. The
// journal is fsynced before an OCI create. A failed or uncertain create keeps
// its original retry token; after 23 hours the command holds for inspection.
// It never regenerates source material or silently rotates a Vault version.
func Provision(ctx context.Context, directory string, target VaultTarget, management VaultClient, bundles BundleClient, now time.Time) (Publication, error) {
	return provision(ctx, directory, target, management, bundles, now, nil)
}

// ProvisionDurable checkpoints the exact publication journal to the source
// authority before any secret create, preserving recovery across host loss.
func ProvisionDurable(ctx context.Context, directory string, target VaultTarget, management VaultClient, bundles BundleClient, now time.Time, checkpoint func([]byte) error) (Publication, error) {
	if checkpoint == nil {
		return Publication{}, ErrProvision
	}
	return provision(ctx, directory, target, management, bundles, now, checkpoint)
}

func provision(ctx context.Context, directory string, target VaultTarget, management VaultClient, bundles BundleClient, now time.Time, checkpoint func([]byte) error) (Publication, error) {
	if management == nil || bundles == nil || ctx.Err() != nil {
		return Publication{}, ErrProvision
	}
	record, err := Load(directory)
	if err != nil || target.validate(record.Config.Region) != nil || !now.Before(record.ExpiresAt) {
		return Publication{}, ErrProvision
	}
	if err := ValidateLive(directory, record); err != nil {
		return Publication{}, ErrProvision
	}
	ctx, cancel := context.WithDeadline(ctx, record.ExpiresAt)
	defer cancel()
	lockFD, err := syscall.Open(filepath.Join(directory, journalLockName), syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return Publication{}, ErrProvision
	}
	lock := os.NewFile(uintptr(lockFD), journalLockName)
	defer lock.Close()
	if err := ownedRegular(filepath.Join(directory, journalLockName), 0, 0); err != nil {
		return Publication{}, ErrProvision
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return Publication{}, ErrProvision
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	metadata, err := readOwnedFile(filepath.Join(directory, metadataName), 1<<20)
	if err != nil {
		return Publication{}, ErrProvision
	}
	materialDigest := digest(metadata)
	state, err := loadJournal(ctx, directory, record, target, materialDigest, checkpoint)
	if err != nil {
		return Publication{}, err
	}
	for index := range state.Entries {
		if ctx.Err() != nil {
			return Publication{}, ErrProvision
		}
		entry := &state.Entries[index]
		file, ok := findFile(record, entry.FileName)
		if !ok {
			return Publication{}, ErrProvision
		}
		if err := publishOne(ctx, directory, target, record.Config.Region, management, bundles, file, entry, &state, now, checkpoint); err != nil {
			return Publication{}, err
		}
	}
	result := Publication{SchemaVersion: 1, Target: target, MaterialSHA256: materialDigest}
	for _, entry := range state.Entries {
		file, _ := findFile(record, entry.FileName)
		if !entry.Verified || entry.SecretOCID == "" {
			return Publication{}, ErrProvision
		}
		result.References = append(result.References, PublicReference{SecretName: entry.Name, Reference: bootstrap.SecretReference{
			Purpose: file.Purpose, Slot: file.Slot, SecretOCID: entry.SecretOCID, VersionNumber: 1,
			SHA256: file.SHA256, MaxBytes: file.MaxBytes, TargetFile: file.Name}})
	}
	return result, nil
}

func findFile(record Record, name string) (File, bool) {
	for _, file := range record.Files {
		if file.Name == name {
			return file, true
		}
	}
	return File{}, false
}

func loadJournal(ctx context.Context, directory string, record Record, target VaultTarget, materialDigest string, checkpoint func([]byte) error) (journal, error) {
	path := filepath.Join(directory, journalName)
	wire, err := readOwnedFile(path, 1<<20)
	if err != nil {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			return journal{}, ErrProvision
		}
		state := journal{SchemaVersion: 1, Target: target, MaterialSHA256: materialDigest}
		for _, file := range record.Files {
			if file.Purpose == "owner-only" {
				continue
			}
			state.Entries = append(state.Entries, journalEntry{Name: secretName(record.Config, file), FileName: file.Name, RetryToken: uuid.New().String()})
		}
		if len(state.Entries) == 0 || len(state.Entries) > 64 {
			return journal{}, ErrProvision
		}
		if err := checkpointJournal(ctx, directory, state, checkpoint); err != nil {
			return journal{}, err
		}
		return state, nil
	}
	var state journal
	if err := json.Unmarshal(wire, &state); err != nil || state.SchemaVersion != 1 || state.Target != target ||
		state.MaterialSHA256 != materialDigest || len(state.Entries) == 0 || len(state.Entries) > 64 {
		return journal{}, ErrProvision
	}
	expected := 0
	for _, file := range record.Files {
		if file.Purpose != "owner-only" {
			expected++
		}
	}
	if len(state.Entries) != expected {
		return journal{}, ErrProvision
	}
	for index, entry := range state.Entries {
		file, ok := findFile(record, entry.FileName)
		if !ok || file.Purpose == "owner-only" || entry.Name != secretName(record.Config, file) ||
			entry.Verified && !regionalResourceOCID(entry.SecretOCID, "vaultsecret", record.Config.Region) ||
			entry.SecretOCID != "" && !regionalResourceOCID(entry.SecretOCID, "vaultsecret", record.Config.Region) ||
			entry.Verified && entry.SentAt.IsZero() || entry.SecretOCID != "" && !entry.Verified ||
			!entry.SentAt.IsZero() && entry.SentAt.Before(record.IssuedAt) {
			return journal{}, ErrProvision
		}
		if _, err := uuid.Parse(entry.RetryToken); err != nil {
			return journal{}, ErrProvision
		}
		if index > 0 && state.Entries[index-1].FileName >= entry.FileName {
			return journal{}, ErrProvision
		}
	}
	if err := checkpointJournal(ctx, directory, state, checkpoint); err != nil {
		return journal{}, err
	}
	return state, nil
}

func checkpointJournal(ctx context.Context, directory string, state journal, checkpoint func([]byte) error) error {
	if err := saveJournal(ctx, directory, state); err != nil {
		return err
	}
	if checkpoint == nil {
		return nil
	}
	wire, err := readOwnedFile(filepath.Join(directory, journalName), 1<<20)
	if err != nil {
		return err
	}
	defer clear(wire)
	if err := GuardPublication(ctx); err != nil {
		return err
	}
	return checkpoint(wire)
}

func secretName(cfg Config, file File) string {
	slot := file.Slot
	if slot == "" {
		slot = "shared"
	}
	sum := sha256.Sum256([]byte(cfg.DeploymentID + "\x00" + cfg.ClusterID))
	return "ts-" + cfg.Environment + "-" + cfg.Region + "-" + strings.ReplaceAll(cfg.DeploymentID, ":", "-") +
		"-" + hex.EncodeToString(sum[:8]) + "-" +
		string(file.Purpose) + "-" + slot + "-" + strings.ReplaceAll(file.Name, ".", "-")
}

func publishOne(ctx context.Context, directory string, target VaultTarget, region string, management VaultClient, bundles BundleClient,
	file File, entry *journalEntry, state *journal, now time.Time, checkpoint func([]byte) error) error {
	id, found, err := lookup(ctx, target, region, entry.Name, management)
	if err != nil {
		return ErrProvision
	}
	if found {
		if entry.SentAt.IsZero() {
			return ErrProvision
		}
		if entry.SecretOCID != "" && entry.SecretOCID != id {
			return ErrProvision
		}
		if err := verifyBundle(ctx, target, id, entry.Name, file, management, bundles); err != nil {
			return ErrProvision
		}
		entry.SecretOCID, entry.Verified = id, true
		return checkpointJournal(ctx, directory, *state, checkpoint)
	}
	if entry.Verified || entry.SecretOCID != "" || !entry.SentAt.IsZero() && (now.Before(entry.SentAt) || now.Sub(entry.SentAt) >= retryWindow) {
		return ErrProvision
	}
	if entry.SentAt.IsZero() {
		entry.SentAt = now.UTC()
		if err := checkpointJournal(ctx, directory, *state, checkpoint); err != nil {
			return err
		}
	}
	if ctx.Err() != nil {
		return ErrProvision
	}
	body, err := readOwnedFile(filepath.Join(directory, file.Name), file.MaxBytes)
	if err != nil || digest(body) != file.SHA256 {
		clear(body)
		return ErrProvision
	}
	encoded := base64.StdEncoding.EncodeToString(body)
	clear(body)
	if ctx.Err() != nil {
		return ErrProvision
	}
	if checkpoint != nil {
		if err := checkpointJournal(ctx, directory, *state, checkpoint); err != nil {
			encoded = ""
			return err
		}
	}
	response, err := management.CreateSecret(ociclient.RequestContext(ctx), ocivault.CreateSecretRequest{
		CreateSecretDetails: ocivault.CreateSecretDetails{
			CompartmentId: new(target.CompartmentOCID), VaultId: new(target.VaultOCID), KeyId: new(target.KMSKeyOCID),
			SecretName: new(entry.Name), Description: new("Initial TerraScale regional controller credential material."),
			SecretContent: ocivault.Base64SecretContentDetails{Content: new(encoded), Stage: ocivault.SecretContentDetailsStageCurrent}},
		OpcRetryToken: new(entry.RetryToken),
	})
	encoded = ""
	if err != nil || response.Id == nil || !regionalResourceOCID(*response.Id, "vaultsecret", region) {
		return ErrProvision
	}
	if err := verifyBundle(ctx, target, *response.Id, entry.Name, file, management, bundles); err != nil {
		return ErrProvision
	}
	entry.SecretOCID, entry.Verified = *response.Id, true
	return checkpointJournal(ctx, directory, *state, checkpoint)
}

func lookup(ctx context.Context, target VaultTarget, region, name string, client VaultClient) (string, bool, error) {
	var page *string
	var found string
	for range 32 {
		response, err := client.ListSecrets(ociclient.RequestContext(ctx), ocivault.ListSecretsRequest{CompartmentId: new(target.CompartmentOCID), VaultId: new(target.VaultOCID), Name: new(name), Page: page})
		if err != nil {
			return "", false, err
		}
		for _, item := range response.Items {
			if item.SecretName == nil || *item.SecretName != name || item.CompartmentId == nil || *item.CompartmentId != target.CompartmentOCID ||
				item.VaultId == nil || *item.VaultId != target.VaultOCID || item.Id == nil || item.LifecycleState != ocivault.SecretSummaryLifecycleStateActive &&
				item.LifecycleState != ocivault.SecretSummaryLifecycleStateCreating {
				return "", false, ErrProvision
			}
			if !regionalResourceOCID(*item.Id, "vaultsecret", region) || found != "" {
				return "", false, ErrProvision
			}
			found = *item.Id
		}
		if response.OpcNextPage == nil {
			return found, found != "", nil
		}
		page = response.OpcNextPage
	}
	return "", false, ErrProvision
}

func verifyBundle(ctx context.Context, target VaultTarget, id, name string, file File, management VaultClient, bundles BundleClient) error {
	deadline := time.Now().Add(time.Minute)
	for {
		response, err := management.GetSecret(ociclient.RequestContext(ctx), ocivault.GetSecretRequest{SecretId: new(id)})
		if err == nil && response.Id != nil && *response.Id == id && response.CompartmentId != nil &&
			*response.CompartmentId == target.CompartmentOCID && response.VaultId != nil && *response.VaultId == target.VaultOCID &&
			response.KeyId != nil && *response.KeyId == target.KMSKeyOCID &&
			response.SecretName != nil && *response.SecretName == name && response.LifecycleState == ocivault.SecretLifecycleStateActive &&
			response.CurrentVersionNumber != nil {
			if *response.CurrentVersionNumber != 1 {
				return ErrProvision
			}
			break
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return ErrProvision
		}
		select {
		case <-ctx.Done():
			return ErrProvision
		case <-time.After(time.Second):
		}
	}
	version := int64(1)
	response, err := bundles.GetSecretBundle(ociclient.RequestContext(ctx), ocisecrets.GetSecretBundleRequest{SecretId: new(id), VersionNumber: &version})
	if err != nil || response.SecretId == nil || *response.SecretId != id || response.VersionNumber == nil || *response.VersionNumber != 1 {
		return ErrProvision
	}
	content, ok := response.SecretBundleContent.(ocisecrets.Base64SecretBundleContentDetails)
	if !ok {
		pointer, pointerOK := response.SecretBundleContent.(*ocisecrets.Base64SecretBundleContentDetails)
		if !pointerOK || pointer == nil {
			return ErrProvision
		}
		content = *pointer
	}
	if content.Content == nil {
		return ErrProvision
	}
	body, err := base64.StdEncoding.Strict().DecodeString(*content.Content)
	if err != nil || int64(len(body)) != file.MaxBytes {
		clear(body)
		return ErrProvision
	}
	defer clear(body)
	want, err := hex.DecodeString(file.SHA256)
	if err != nil {
		return ErrProvision
	}
	sum := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(sum[:], want) != 1 {
		return ErrProvision
	}
	return nil
}

func saveJournal(ctx context.Context, directory string, state journal) error {
	wire, err := json.Marshal(state)
	if err != nil {
		return ErrProvision
	}
	temporary := filepath.Join(directory, journalTempName)
	if _, err := os.Lstat(temporary); err == nil {
		if err := ownedRegular(temporary, 0, 1<<20); err != nil {
			return ErrProvision
		}
		if err := os.Remove(temporary); err != nil {
			return ErrProvision
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrProvision
	}
	if err := writeOnce(temporary, wire); err != nil {
		return ErrProvision
	}
	defer os.Remove(temporary)
	if err := GuardPublication(ctx); err != nil {
		return err
	}
	if err := os.Rename(temporary, filepath.Join(directory, journalName)); err != nil {
		return ErrProvision
	}
	if err := syncDirectory(directory); err != nil {
		return ErrProvision
	}
	return GuardPublication(ctx)
}

// ValidatePublication binds public host references to a complete, exact source
// journal. Owner-only escrow material cannot appear in a host publication.
func ValidatePublication(directory string, publication Publication, journalWire []byte) error {
	record, err := Load(directory)
	if err != nil {
		return ErrProvision
	}
	return validatePublication(directory, record, publication, journalWire)
}

func validatePublication(directory string, record Record, publication Publication, journalWire []byte) error {
	if publication.SchemaVersion != 1 || publication.Target.Validate(record.Config.Region) != nil {
		return ErrProvision
	}
	metadata, err := readOwnedFile(filepath.Join(directory, metadataName), 1<<20)
	if err != nil || publication.MaterialSHA256 != digest(metadata) {
		return ErrProvision
	}
	var state journal
	if json.Unmarshal(journalWire, &state, json.RejectUnknownMembers(true)) != nil || state.SchemaVersion != 1 || state.Target != publication.Target || state.MaterialSHA256 != publication.MaterialSHA256 || len(state.Entries) != len(publication.References) {
		return ErrProvision
	}
	expected := 0
	for _, file := range record.Files {
		if file.Purpose != "owner-only" {
			expected++
		}
	}
	if len(state.Entries) != expected {
		return ErrProvision
	}
	for index, entry := range state.Entries {
		file, ok := findFile(record, entry.FileName)
		if !ok || file.Purpose == "owner-only" || entry.Name != secretName(record.Config, file) || !entry.Verified || entry.SentAt.IsZero() || !regionalResourceOCID(entry.SecretOCID, "vaultsecret", record.Config.Region) || index > 0 && state.Entries[index-1].FileName >= entry.FileName {
			return ErrProvision
		}
		if _, err := uuid.Parse(entry.RetryToken); err != nil {
			return ErrProvision
		}
		want := PublicReference{SecretName: entry.Name, Reference: bootstrap.SecretReference{Purpose: file.Purpose, Slot: file.Slot, SecretOCID: entry.SecretOCID, VersionNumber: 1, SHA256: file.SHA256, MaxBytes: file.MaxBytes, TargetFile: file.Name}}
		if publication.References[index] != want {
			return ErrProvision
		}
	}
	return nil
}
