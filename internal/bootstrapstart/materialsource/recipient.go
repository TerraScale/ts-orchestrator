package materialsource

import (
	"context"
	"encoding/json/v2"
	"reflect"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
)

func (inputs *linkInputs) regionalRecord() (bootstrapmaterial.Record, error) {
	if inputs.recipient == nil {
		if inputs.regional == nil {
			return bootstrapmaterial.Record{}, ErrMaterialSource
		}
		return inputs.regional.Record(), nil
	}
	wire := inputs.recipient.MaterialRecord()
	var record bootstrapmaterial.Record
	if digestWire(wire) != inputs.regionalDigest || json.Unmarshal(wire, &record, json.RejectUnknownMembers(true)) != nil || !reflect.DeepEqual(record.Config, inputs.recipientGrant.Config()) {
		return bootstrapmaterial.Record{}, ErrMaterialSource
	}
	return record, nil
}

func (inputs *linkInputs) verifyRecipient(ctx context.Context) error {
	recipient, grant, home, link := inputs.recipient, inputs.recipientGrant, inputs.home, inputs.homeLink
	if recipient == nil || inputs.regional != nil || !grant.IsVerified() || !time.Now().Before(grant.ExpiresAt()) || recipient.VerifyCurrent(ctx, time.Now()) != nil || home == nil || home.kind != "" || link == nil || link.source == nil || link.source.link == nil {
		return ErrMaterialSource
	}
	cfg, homeCfg := grant.Config(), home.grant.Config()
	if homeCfg.Cell != natscell.LinkHome || cfg.Cell == natscell.LinkHome || cfg.Environment != homeCfg.Environment || cfg.DeploymentID != homeCfg.DeploymentID || grant.InstallationID() != home.grant.InstallationID() || grant.Generation() != home.grant.Generation() || grant.EscrowTarget() != home.grant.EscrowTarget() || grant.StorageDomain() != home.grant.StorageDomain() {
		return ErrMaterialSource
	}
	grantDigest := digestWire(grant.FoundationGrantWire())
	if grantDigest != digestWire(home.grant.FoundationGrantWire()) || recipient.GrantDigest() != grantDigest || recipient.InstallationID() != grant.InstallationID() || recipient.Generation() != grant.Generation() || strings.ToLower(string(recipient.Cell())) != cfg.Cell || recipient.StorageDomain() != grant.StorageDomain() {
		return ErrMaterialSource
	}
	if recipient.SourceSHA256() != inputs.regionalDigest || recipient.HomeSHA256() != inputs.homeDigest || inputs.homeDigest != digestWire(home.archive.Files["material.json"]) || recipient.VerifyHome(home.archive.Files["material.json"]) != nil {
		return ErrMaterialSource
	}
	if _, err := inputs.regionalRecord(); err != nil {
		return err
	}
	if err := home.verifySource(ctx); err != nil {
		return err
	}
	if link.record.Config.Cell != natscell.LinkHome || link.source.grant.InstallationID() != grant.InstallationID() || link.source.grant.Generation() != grant.Generation() || link.record.SourceSHA256 != inputs.homeDigest || link.record.HomeSHA256 != inputs.homeDigest || inputs.homeLinkDigest != digestWire(link.source.archive.Files["material.json"]) {
		return ErrMaterialSource
	}
	return link.source.verifySource(ctx)
}

func (source *ColdStartMaterial) publicationTargetAllowed(target bootstrapmaterial.VaultTarget) bool {
	if source.link == nil || source.link.recipient == nil {
		return true
	}
	expected := source.link.recipient.VaultTarget()
	return target.CompartmentOCID == expected.CompartmentOCID && target.VaultOCID == expected.VaultOCID && target.KMSKeyOCID == expected.KMSKeyOCID
}
