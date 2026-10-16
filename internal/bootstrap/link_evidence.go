package bootstrap

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/nats-io/nkeys"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// RegionalLinkEvidence is public, reproducible startup provenance. Spoke delivery
// is signed by the registered home source; the home uses its exact own CAS.
type RegionalLinkEvidence struct {
	SourceObjectKey string            `json:"sourceObjectKey"`
	SourceSHA256    string            `json:"sourceSha256"`
	MaterialRecord  []byte            `json:"materialRecord"`
	Journal         []byte            `json:"journal"`
	References      []SecretReference `json:"references"`
	Delivery        []byte            `json:"delivery,omitempty"`
}

type VerifiedStartupLink struct {
	template VerifiedStartupTemplate
	client   ObjectStorageClient
	evidence RegionalLinkEvidence
}

func (link VerifiedStartupLink) IsVerified() bool {
	return link.client != nil && link.template.IsVerified() && link.evidence.SourceObjectKey != ""
}
func (link VerifiedStartupLink) MaterialRecord() []byte {
	return bytes.Clone(link.evidence.MaterialRecord)
}
func (link VerifiedStartupLink) References() []SecretReference {
	return slices.Clone(link.evidence.References)
}
func (link VerifiedStartupLink) Evidence() RegionalLinkEvidence {
	e := link.evidence
	e.MaterialRecord = bytes.Clone(e.MaterialRecord)
	e.Journal = bytes.Clone(e.Journal)
	e.Delivery = bytes.Clone(e.Delivery)
	e.References = slices.Clone(e.References)
	return e
}
func (link VerifiedStartupLink) VerifyCurrent(ctx context.Context, now time.Time) error {
	if !link.IsVerified() {
		return ErrManifestInvalid
	}
	_, err := VerifyStartupLink(ctx, link.template, link.client, link.evidence, now)
	return err
}

// LinkDeliveryPayload excludes its own signature from the exact signed payload.
func LinkDeliveryPayload(evidence RegionalLinkEvidence) ([]byte, error) {
	evidence.Delivery = nil
	return json.Marshal(evidence, json.Deterministic(true))
}

func VerifyStartupLink(ctx context.Context, template VerifiedStartupTemplate, client ObjectStorageClient, evidence RegionalLinkEvidence, now time.Time) (VerifiedStartupLink, error) {
	deny := func() (VerifiedStartupLink, error) { return VerifiedStartupLink{}, ErrManifestInvalid }
	if ctx.Err() != nil || client == nil || template.VerifyCurrentContext(ctx, now) != nil || !validDigest(evidence.SourceSHA256) || len(evidence.MaterialRecord) == 0 || len(evidence.MaterialRecord) > 48<<10 || len(evidence.Journal) == 0 || len(evidence.Journal) > 64<<10 {
		return deny()
	}
	regional, err := LoadRegionalSource(ctx, template, client, now)
	if err != nil {
		return deny()
	}
	homeTemplate, err := template.ForCell(ctx, oci.RegionGRU, now)
	if err != nil {
		return deny()
	}
	home, err := LoadRegionalSource(ctx, homeTemplate, client, now)
	if err != nil {
		return deny()
	}
	isHome := template.startupIdentity().Cell == oci.RegionGRU
	kind := "spoke-link-v1"
	binding := ""
	key := ""
	if isHome {
		kind = "link"
		wire, _ := json.Marshal([]string{"link", digestBytes(regional.MaterialRecord()), digestBytes(home.MaterialRecord()), ""}, json.Deterministic(true))
		binding = digestBytes(wire)
		scope := digestBytes([]byte(template.InstallationID() + "\x00gru\x00link\x00" + binding))
		key = home.StorageDomain().Prefix + "/bootstrap/v2/material-source/link-" + scope + ".json"
		if len(evidence.Delivery) != 0 {
			return deny()
		}
	} else {
		recipient, err := VerifyLinkRecipient(ctx, regional, home, now)
		if err != nil {
			return deny()
		}
		binding = recipient.BindingSHA256()
		key = recipient.LinkObjectKey()
		payload, err := VerifyLinkDelivery(ctx, recipient, evidence.Delivery, now)
		want, encodeErr := LinkDeliveryPayload(evidence)
		if err != nil || encodeErr != nil || !bytes.Equal(payload, want) {
			return deny()
		}
	}
	if evidence.SourceObjectKey != key {
		return deny()
	}
	domain := home.StorageDomain()
	response, err := client.GetObject(ociclient.RequestContext(ctx), objectstorage.GetObjectRequest{NamespaceName: new(domain.Namespace), BucketName: new(domain.HeadBucket), ObjectName: new(key)})
	if err != nil {
		return VerifiedStartupLink{}, err
	}
	if response.Content == nil {
		return deny()
	}
	defer response.Content.Close()
	stateWire, err := io.ReadAll(io.LimitReader(response.Content, 2<<20))
	if err != nil || len(stateWire) >= 2<<20 || response.ETag == nil || *response.ETag == "" {
		return deny()
	}
	var state struct {
		Actor          SourceInventoryActor `json:"actor"`
		SchemaVersion  int                  `json:"schemaVersion"`
		Kind           string               `json:"kind"`
		BindingSHA256  string               `json:"bindingSha256"`
		InstallationID string               `json:"installationId"`
		Cell           string               `json:"cell"`
		Generation     uint64               `json:"generation"`
		PlanSHA256     string               `json:"planSha256"`
		Target         StartupVaultTarget   `json:"target"`
		Reference      struct {
			SecretOCID string `json:"secretOcid"`
			SHA256     string `json:"sha256"`
			MaxBytes   int64  `json:"maxBytes"`
		} `json:"reference"`
		Journal  []byte `json:"journal"`
		Delivery []byte `json:"delivery"`
	}
	if json.Unmarshal(stateWire, &state) != nil || state.SchemaVersion != 1 || state.Actor != home.OriginalActor() || state.Kind != kind || state.BindingSHA256 != binding || state.InstallationID != template.InstallationID() || state.Cell != strings.ToLower(string(template.startupIdentity().Cell)) || state.Generation == 0 || state.Generation > template.Generation() || state.PlanSHA256 != template.PlanDigest() || state.Target != template.escrow || !isOCID(state.Reference.SecretOCID, "vaultsecret") || state.Reference.SHA256 != evidence.SourceSHA256 || state.Reference.MaxBytes <= 0 || state.Reference.MaxBytes > 25<<10 || !bytes.Equal(state.Journal, evidence.Journal) || !bytes.Equal(state.Delivery, evidence.Delivery) {
		return deny()
	}
	var record struct {
		SchemaVersion  int            `json:"schemaVersion"`
		Config         jsontext.Value `json:"config"`
		Public         jsontext.Value `json:"public"`
		IssuedAt       time.Time      `json:"issuedAt"`
		ExpiresAt      time.Time      `json:"expiresAt"`
		SourceSHA256   string         `json:"sourceSha256"`
		HomeSHA256     string         `json:"homeSha256"`
		HomeLinkSHA256 string         `json:"homeLinkSha256"`
		HomeAccount    string         `json:"homeAccount"`
		Signer         string         `json:"signer"`
		Files          []struct {
			Name     string        `json:"name"`
			Purpose  SecretPurpose `json:"purpose"`
			Slot     string        `json:"slot"`
			SHA256   string        `json:"sha256"`
			MaxBytes int64         `json:"maxBytes"`
		} `json:"files"`
	}
	var sourceRecord struct {
		Public jsontext.Value `json:"public"`
	}
	var homeRecord struct {
		Public struct {
			CellAccountNKey string `json:"cellAccountNkey"`
		} `json:"public"`
	}
	if json.Unmarshal(evidence.MaterialRecord, &record) != nil || json.Unmarshal(regional.MaterialRecord(), &sourceRecord) != nil || json.Unmarshal(home.MaterialRecord(), &homeRecord) != nil || record.SchemaVersion != 1 || digestBytes(record.Config) != template.PlanDigest() || !bytes.Equal(record.Public, sourceRecord.Public) || record.IssuedAt.IsZero() || now.Before(record.IssuedAt) || !now.Before(record.ExpiresAt) || record.SourceSHA256 != digestBytes(regional.MaterialRecord()) || record.HomeSHA256 != digestBytes(home.MaterialRecord()) || record.HomeAccount != homeRecord.Public.CellAccountNKey || !nkeys.IsValidPublicAccountKey(record.Signer) || record.Signer == record.HomeAccount || !isHome && !validDigest(record.HomeLinkSHA256) || isHome && record.HomeLinkSHA256 != "" {
		return deny()
	}
	var journal struct {
		SchemaVersion  int                `json:"schemaVersion"`
		Target         StartupVaultTarget `json:"target"`
		MaterialSHA256 string             `json:"materialSha256"`
		Entries        []struct {
			FileName   string `json:"fileName"`
			SecretOCID string `json:"secretOcid"`
			Verified   bool   `json:"verified"`
		} `json:"entries"`
	}
	if json.Unmarshal(evidence.Journal, &journal) != nil || journal.SchemaVersion != 1 || journal.Target != template.VaultTarget() || journal.MaterialSHA256 != digestBytes(evidence.MaterialRecord) {
		return deny()
	}
	expected := map[string]string{"interregion-ca.pem": ""}
	if isHome {
		expected["link-cell.jwt"] = ""
		expected["issuer-link.seed"] = ""
	} else {
		expected[LinkCredentialsFile] = ""
	}
	for _, slot := range template.startupIdentity().ControllerSlots {
		cert, key := InterRegionTLSFiles(slot)
		expected[cert] = slot
		expected[key] = slot
	}
	if len(record.Files) != len(expected) {
		return deny()
	}
	seen := make(map[string]bool, len(expected))
	count := 0
	for _, file := range record.Files {
		slot, ok := expected[file.Name]
		if !ok || seen[file.Name] || slot != file.Slot || !validDigest(file.SHA256) || file.MaxBytes <= 0 || file.MaxBytes > MaxSecretBytes {
			return deny()
		}
		seen[file.Name] = true
		purpose := SecretInterRegion
		if file.Name == "issuer-link.seed" {
			purpose = "owner-only"
		} else if file.Name == "link-cell.jwt" {
			purpose = SecretRegionalShared
		}
		if file.Purpose != purpose {
			return deny()
		}
		if purpose == "owner-only" {
			continue
		}
		count++
		target := file.Name
		if target == "link-cell.jwt" {
			target = "cell.jwt"
		}
		i := slices.IndexFunc(evidence.References, func(ref SecretReference) bool { return ref.TargetFile == target })
		if i < 0 {
			return deny()
		}
		ref := evidence.References[i]
		if ref.Purpose != file.Purpose || ref.Slot != file.Slot || ref.SHA256 != file.SHA256 || ref.MaxBytes != file.MaxBytes || ref.VersionNumber != 1 || !isOCID(ref.SecretOCID, "vaultsecret") {
			return deny()
		}
		j := slices.IndexFunc(journal.Entries, func(entry struct {
			FileName   string `json:"fileName"`
			SecretOCID string `json:"secretOcid"`
			Verified   bool   `json:"verified"`
		}) bool {
			return entry.FileName == file.Name && entry.Verified && entry.SecretOCID == ref.SecretOCID
		})
		if j < 0 {
			return deny()
		}
	}
	if count != len(evidence.References) || count != len(journal.Entries) {
		return deny()
	}
	verified := VerifiedStartupLink{template: template, client: client, evidence: evidence}
	verified.evidence = verified.Evidence()
	return verified, nil
}
