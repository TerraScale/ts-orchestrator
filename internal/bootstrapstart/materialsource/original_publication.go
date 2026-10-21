package materialsource

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
	"uuid"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

type originalPublicationContext struct {
	context.Context
	values context.Context
}

func (ctx originalPublicationContext) Value(key any) any {
	return ctx.values.Value(key)
}

// Preserve caller guards without reentering publication, and use dispatch lifetime.
func originalPublicationCheckpointContext(dispatch, caller context.Context) context.Context {
	return ociclient.CheckpointContext(originalPublicationContext{Context: dispatch, values: caller})
}

type originalMaterialPublicationState struct {
	Scope   region.OriginalMaterialPublicationScope `json:"scope"`
	Journal []byte                                  `json:"journal,omitempty"`
	Result  *bootstrapmaterial.Publication          `json:"result,omitempty"`
}

type originalPublicationEntry struct {
	Name       string    `json:"name"`
	FileName   string    `json:"fileName"`
	RetryToken string    `json:"retryToken"`
	SentAt     time.Time `json:"sentAt"`
	SecretOCID string    `json:"secretOcid,omitempty"`
	Verified   bool      `json:"verified"`
}

type originalPublicationJournal struct {
	SchemaVersion  int                           `json:"schemaVersion"`
	Target         bootstrapmaterial.VaultTarget `json:"target"`
	MaterialSHA256 string                        `json:"materialSha256"`
	Entries        []originalPublicationEntry    `json:"entries"`
}

func originalPublicationRecord(state originalSourceState, in originalSourceInputs) (bootstrapmaterial.Record, string, error) {
	var record bootstrapmaterial.Record
	envelope, err := trust.DecodeEnvelope(state.OriginalAdmissionInventory)
	if err != nil {
		return record, "", err
	}
	var binding bootstrap.RegionalSourceInventory
	if json.Unmarshal(envelope.Payload, &binding, json.RejectUnknownMembers(true)) != nil ||
		binding.SourceSHA256 != state.Reference.SHA256 || binding.GrantSHA256 != in.scope.GrantSHA256 || binding.PlanSHA256 != in.scope.PlanSHA256 ||
		json.Unmarshal(binding.MaterialRecord, &record, json.RejectUnknownMembers(true)) != nil {
		return record, "", ErrMaterialSource
	}
	config, err := json.Marshal(record.Config, json.Deterministic(true))
	if err != nil || digestWire(config) != in.scope.PlanSHA256 || bootstrapmaterial.ValidateAdmissionInventory(record) != nil {
		return record, "", ErrMaterialSource
	}
	return record, digestWire(binding.MaterialRecord), nil
}

func originalPublicationFile(record bootstrapmaterial.Record, name string) (bootstrapmaterial.File, bool) {
	for _, file := range record.Files {
		if file.Name == name && file.Purpose != "owner-only" {
			return file, true
		}
	}
	return bootstrapmaterial.File{}, false
}

func originalRegionalSecret(id, region string) bool {
	prefix := "ocid1.vaultsecret.oc1." + region + "."
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

func originalPublicationJournalFor(state originalSourceState, in originalSourceInputs) (originalPublicationJournal, bool) {
	var journal originalPublicationJournal
	p := state.Publication
	if p == nil || len(p.Journal) == 0 || len(p.Journal) > 1<<20 {
		return journal, false
	}
	record, material, err := originalPublicationRecord(state, in)
	if err != nil || json.Unmarshal(p.Journal, &journal, json.RejectUnknownMembers(true)) != nil || journal.SchemaVersion != 1 ||
		journal.Target != p.Scope.Target || journal.MaterialSHA256 != material || len(journal.Entries) != 33 {
		return journal, false
	}
	seen := map[string]bool{}
	ids := map[string]bool{}
	for index, entry := range journal.Entries {
		file, ok := originalPublicationFile(record, entry.FileName)
		name, err := bootstrapmaterial.OriginalPublicationSecretName(in.config, file)
		token, tokenErr := uuid.Parse(entry.RetryToken)
		if !ok || err != nil || entry.Name != name || seen[entry.Name] || tokenErr != nil || token.String() != entry.RetryToken ||
			index > 0 && journal.Entries[index-1].FileName >= entry.FileName ||
			!entry.SentAt.IsZero() && (entry.SentAt.Before(state.StartedAt) || entry.SentAt.After(time.Now()) || !entry.SentAt.Before(in.scope.Deadline)) ||
			entry.Verified != (entry.SecretOCID != "") || entry.Verified && entry.SentAt.IsZero() ||
			entry.SecretOCID != "" && (!originalRegionalSecret(entry.SecretOCID, in.config.Region) || ids[entry.SecretOCID]) {
			return journal, false
		}
		seen[entry.Name] = true
		if entry.SecretOCID != "" {
			ids[entry.SecretOCID] = true
		}
	}
	return journal, true
}

func validOriginalPublication(state originalSourceState, in originalSourceInputs) bool {
	p := state.Publication
	if p == nil {
		return true
	}
	scope := p.Scope
	if state.Reference == (materialSourceReference{}) || len(state.OriginalAdmissionInventory) == 0 ||
		scope.Target.Validate(in.config.Region) != nil || !strings.HasPrefix(scope.PolicyID, "ocid1.policy.oc1..") || len(scope.PolicyID) <= len("ocid1.policy.oc1..") || len(scope.PolicyID) > 512 || strings.ContainsAny(scope.PolicyID, "\x00\r\n /\\") ||
		scope.PolicyETag == "" || len(scope.PolicyETag) > 1024 || strings.ContainsAny(scope.PolicyETag, "\x00\r\n") ||
		!validDigest(scope.PolicySHA256) || !validDigest(scope.ReadbackSHA256) {
		return false
	}
	if len(p.Journal) == 0 {
		return p.Result == nil
	}
	journal, ok := originalPublicationJournalFor(state, in)
	if !ok {
		return false
	}
	if p.Result == nil {
		return true
	}
	result := p.Result
	if result.SchemaVersion != 1 || result.Target != scope.Target || result.MaterialSHA256 != journal.MaterialSHA256 || len(result.References) != len(journal.Entries) {
		return false
	}
	record, _, err := originalPublicationRecord(state, in)
	if err != nil {
		return false
	}
	ids := map[string]bool{}
	for index, ref := range result.References {
		entry := journal.Entries[index]
		file, ok := originalPublicationFile(record, entry.FileName)
		r := ref.Reference
		if !ok || !entry.Verified || ref.SecretName != entry.Name || r.SecretOCID != entry.SecretOCID || ids[r.SecretOCID] ||
			r.VersionNumber != 1 || r.Purpose != file.Purpose || r.Slot != file.Slot || r.TargetFile != file.Name || r.SHA256 != file.SHA256 || r.MaxBytes != file.MaxBytes {
			return false
		}
		ids[r.SecretOCID] = true
	}
	return true
}

func immutableOriginalPublication(prior, next originalSourceState) bool {
	a, b := prior.Publication, next.Publication
	if a == nil {
		return b == nil || len(prior.OriginalAdmissionInventory) != 0 && len(b.Journal) == 0 && b.Result == nil
	}
	if b == nil || a.Scope != b.Scope {
		return false
	}
	if a.Result != nil {
		return bytes.Equal(marshalOriginalPublication(a), marshalOriginalPublication(b))
	}
	if len(a.Journal) == 0 {
		if len(b.Journal) == 0 {
			return b.Result == nil
		}
		var journal originalPublicationJournal
		if json.Unmarshal(b.Journal, &journal, json.RejectUnknownMembers(true)) != nil || b.Result != nil {
			return false
		}
		for _, entry := range journal.Entries {
			if !entry.SentAt.IsZero() || entry.SecretOCID != "" || entry.Verified {
				return false
			}
		}
		return true
	}
	if len(b.Journal) == 0 {
		return false
	}
	var before, after originalPublicationJournal
	if json.Unmarshal(a.Journal, &before, json.RejectUnknownMembers(true)) != nil || json.Unmarshal(b.Journal, &after, json.RejectUnknownMembers(true)) != nil ||
		before.SchemaVersion != after.SchemaVersion || before.Target != after.Target || before.MaterialSHA256 != after.MaterialSHA256 || len(before.Entries) != len(after.Entries) {
		return false
	}
	for index, old := range before.Entries {
		current := after.Entries[index]
		if old.Name != current.Name || old.FileName != current.FileName || old.RetryToken != current.RetryToken ||
			!old.SentAt.IsZero() && !old.SentAt.Equal(current.SentAt) || old.SecretOCID != "" && old.SecretOCID != current.SecretOCID || old.Verified && !current.Verified ||
			old.SentAt.IsZero() && (current.SecretOCID != "" || current.Verified) {
			return false
		}
	}
	if b.Result != nil {
		if !bytes.Equal(a.Journal, b.Journal) {
			return false
		}
		for _, entry := range before.Entries {
			if !entry.Verified {
				return false
			}
		}
	}
	return true
}

func marshalOriginalPublication(p *originalMaterialPublicationState) []byte {
	wire, _ := json.Marshal(p, json.Deterministic(true))
	return wire
}

// PublishRegionalMaterial consumes genuine archive custody without constructing
// an ordinary founder or granting installation, ledger or startup authority.
func (v *VerifiedOriginalSourceArchive) PublishRegionalMaterial(ctx context.Context, now time.Time) error {
	if v == nil || !v.IsVerified() || ctx == nil || ctx.Err() != nil || now.IsZero() {
		return ErrMaterialSource
	}
	_, unlock, err := lockOriginalDirectory(v.directory)
	if err != nil {
		return err
	}
	defer unlock()
	if err := v.VerifyCurrent(ctx); err != nil {
		return err
	}
	scope, factory, materialCtx, err := v.actor.MaterialPublication(ctx)
	if err != nil {
		return err
	}
	clients, _, err := originalClients(ctx, v.actor)
	if err != nil {
		return err
	}
	guard := func(send context.Context) error {
		if err := send.Err(); err != nil {
			return err
		}
		check := originalPublicationCheckpointContext(send, ctx)
		currentScope, _, _, err := v.actor.MaterialPublication(check)
		if err != nil || currentScope != scope {
			return errors.Join(ErrMaterialSource, err)
		}
		current, observed, err := readOriginalState(check, clients.objects, v.inputs)
		if err != nil || observed != v.etag || !sameOriginalState(current, v.state) {
			return errors.Join(ErrMaterialSource, err)
		}
		return ociclient.LimitAdmission(send, v.inputs.scope.Deadline)
	}
	guarded := ociclient.WithRequestGuard(ociclient.WithAuthority(materialCtx, guard), guard)
	checkpoint := func(next originalSourceState) error {
		etag, err := writeOriginalState(guarded, materialCtx, clients.objects, v.inputs, next, v.etag)
		if err != nil {
			return err
		}
		v.state, v.etag = next, etag
		return nil
	}
	if err := guard(ctx); err != nil {
		return err
	}
	body, _, err := readOriginalVault(guarded, clients, v.state)
	if err != nil {
		return err
	}
	defer clear(body)
	archive, record, err := decodeOriginalCandidate(v.directory, v.inputs, v.state, body)
	if err != nil {
		return err
	}
	defer clearArchive(archive)
	if _, err := originalInventory(v.inputs, v.state, archive, record); err != nil {
		return err
	}
	if v.state.Publication == nil {
		next := v.state
		next.Publication = &originalMaterialPublicationState{Scope: scope}
		if err := checkpoint(next); err != nil {
			return err
		}
	} else if v.state.Publication.Scope != scope {
		return ErrMaterialSource
	}
	regional, err := factory.ForRegion(v.inputs.config.Region)
	if err != nil {
		return err
	}
	management, err := ocivault.NewVaultsClientWithConfigurationProvider(regional.Provider())
	if err != nil {
		return err
	}
	management.SetRegion(v.inputs.config.Region)
	regional.Configure(&management.BaseClient, ociclient.ServiceVault)
	bundles, err := vaultsecret.SecretsClient(regional)
	if err != nil {
		return err
	}
	directory, err := os.MkdirTemp(v.directory, ".original-publication-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	for name, data := range archive.Files {
		if filepath.Base(name) != name || name == "publication.json" || name == "publication.lock" || name == ".publication.tmp" {
			return ErrMaterialSource
		}
		if err := writeSourceFile(filepath.Join(directory, name), data); err != nil {
			return err
		}
	}
	if len(v.state.Publication.Journal) != 0 {
		if err := writeSourceFile(filepath.Join(directory, "publication.json"), v.state.Publication.Journal); err != nil {
			return err
		}
	}
	if err := syncSourceDirectory(directory); err != nil {
		return err
	}
	guarded = bootstrapmaterial.WithPublicationGuard(guarded, guard)
	publication, err := bootstrapmaterial.ProvisionDurable(guarded, directory, scope.Target, &management, &bundles, now, func(journal []byte) error {
		if bytes.Equal(v.state.Publication.Journal, journal) {
			return guard(ctx)
		}
		next := v.state
		p := *v.state.Publication
		p.Journal = bytes.Clone(journal)
		next.Publication = &p
		return checkpoint(next)
	})
	if err != nil {
		return err
	}
	if err := bootstrapmaterial.ValidatePublication(directory, publication, v.state.Publication.Journal); err != nil {
		return err
	}
	next := v.state
	p := *v.state.Publication
	p.Result = &publication
	next.Publication = &p
	if !validOriginalPublication(next, v.inputs) {
		return ErrMaterialSource
	}
	if v.state.Publication.Result == nil {
		if err := checkpoint(next); err != nil {
			return err
		}
	} else if !bytes.Equal(marshalOriginalPublication(v.state.Publication), marshalOriginalPublication(next.Publication)) {
		return ErrMaterialSource
	}
	return guard(ctx)
}
