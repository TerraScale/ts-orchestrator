package materialsource

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"reflect"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/region"
)

type linkInputs struct {
	regional, home                             *ColdStartMaterial
	homeLink                                   *LinkSource
	regionalDigest, homeDigest, homeLinkDigest string
}

// LinkSource retains the recovered founder-only Link signer and its durable publication.
type LinkSource struct {
	source *ColdStartMaterial
	record bootstrapmaterial.LinkRecord
}

// ResolveLinkSource binds Link recovery to the original regional and home roots.
// Spokes require the recovered home Link source; the home passes nil homeLink.
func ResolveLinkSource(ctx context.Context, regional, home *ColdStartMaterial, homeLink *LinkSource, objects bootstrapstart.FounderSelectionObjectWriter, management bootstrapmaterial.VaultClient, bundles EscrowClient, directory string, now time.Time) (*LinkSource, error) {
	if regional == nil || home == nil || regional.kind != "" || home.kind != "" || objects == nil || management == nil || bundles == nil || now.IsZero() || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, ErrMaterialSource
	}
	inputs := &linkInputs{regional: regional, home: home, homeLink: homeLink, regionalDigest: digestWire(regional.archive.Files["material.json"]), homeDigest: digestWire(home.archive.Files["material.json"])}
	if homeLink != nil && homeLink.source == nil {
		return nil, ErrMaterialSource
	}
	if homeLink != nil {
		inputs.homeLinkDigest = digestWire(homeLink.source.archive.Files["material.json"])
	}
	if err := inputs.verify(ctx); err != nil {
		return nil, err
	}
	bindingWire, err := json.Marshal([]string{"link", inputs.regionalDigest, inputs.homeDigest, inputs.homeLinkDigest}, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	binding := digestWire(bindingWire)
	grant := regional.grant
	scope := sha256.Sum256([]byte(grant.InstallationID() + "\x00" + grant.Config().Cell + "\x00link\x00" + binding))
	source := &ColdStartMaterial{grant: grant, objects: objects, directory: directory, kind: "link", binding: binding, link: inputs, secretName: "ts-bootstrap-source-link-" + hex.EncodeToString(scope[:16]), key: grant.StorageDomain().Prefix + "/bootstrap/v2/material-source/link-" + hex.EncodeToString(scope[:]) + ".json"}
	source, err = resolveSource(ctx, source, management, bundles, now)
	if err != nil {
		return nil, err
	}
	record, err := bootstrapmaterial.LoadLink(directory, now)
	if err != nil {
		return nil, err
	}
	return &LinkSource{source: source, record: record}, nil
}

func (inputs *linkInputs) verify(ctx context.Context) error {
	regional, home := inputs.regional, inputs.home
	if regional == nil || home == nil || regional.kind != "" || home.kind != "" || home.grant.Config().Cell != natscell.LinkHome || regional.grant.InstallationID() != home.grant.InstallationID() || regional.grant.Generation() != home.grant.Generation() || regional.grant.EscrowTarget() != home.grant.EscrowTarget() || regional.grant.StorageDomain() != home.grant.StorageDomain() {
		return ErrMaterialSource
	}
	cfg, homeCfg := regional.grant.Config(), home.grant.Config()
	if cfg.Environment != homeCfg.Environment || cfg.DeploymentID != homeCfg.DeploymentID || inputs.regionalDigest != digestWire(regional.archive.Files["material.json"]) || inputs.homeDigest != digestWire(home.archive.Files["material.json"]) {
		return ErrMaterialSource
	}
	if err := regional.verifySource(ctx); err != nil {
		return err
	}
	if err := home.verifySource(ctx); err != nil {
		return err
	}
	if cfg.Cell == natscell.LinkHome {
		if inputs.homeLink != nil || inputs.regionalDigest != inputs.homeDigest || !reflect.DeepEqual(cfg, homeCfg) {
			return ErrMaterialSource
		}
		return nil
	}
	link := inputs.homeLink
	if link == nil || link.source == nil || link.source.link == nil || link.record.Config.Cell != natscell.LinkHome || link.source.grant.InstallationID() != regional.grant.InstallationID() || link.source.grant.Generation() != regional.grant.Generation() || link.record.SourceSHA256 != inputs.homeDigest || link.record.HomeSHA256 != inputs.homeDigest || inputs.homeLinkDigest != digestWire(link.source.archive.Files["material.json"]) {
		return ErrMaterialSource
	}
	return link.source.verifySource(ctx)
}

func (source *ColdStartMaterial) verifySource(ctx context.Context) error {
	if source == nil || !source.grant.IsVerified() || !time.Now().Before(source.grant.ExpiresAt()) || ctx.Err() != nil {
		return ErrMaterialSource
	}
	if source.link != nil {
		if err := source.link.verify(ctx); err != nil {
			return err
		}
	}
	state, _, err := source.read(ctx)
	defer clear(state.Journal)
	if err != nil || state.Reference != source.state.Reference || state.Reference.SecretOCID == "" {
		return ErrMaterialSource
	}
	if _, err := source.loadRecord(source.directory); err != nil {
		return err
	}
	for name, expected := range source.archive.Files {
		actual, err := os.ReadFile(filepath.Join(source.directory, name))
		same := err == nil && bytes.Equal(actual, expected)
		clear(actual)
		if !same {
			return ErrMaterialSource
		}
	}
	return nil
}

func (source *ColdStartMaterial) loadRecord(directory string) (bootstrapmaterial.Record, error) {
	if source.link == nil {
		record, err := bootstrapmaterial.Load(directory)
		if err != nil {
			return bootstrapmaterial.Record{}, err
		}
		if err := bootstrapmaterial.ValidateLive(directory, record); err != nil {
			return bootstrapmaterial.Record{}, err
		}
		if err := source.validateLedger(record); err != nil {
			return bootstrapmaterial.Record{}, err
		}
		return record, nil
	}
	record, err := bootstrapmaterial.LoadLink(directory, time.Now())
	if err != nil || record.SourceSHA256 != source.link.regionalDigest || record.HomeSHA256 != source.link.homeDigest || record.HomeLinkSHA256 != source.link.homeLinkDigest || !reflect.DeepEqual(record.Config, source.grant.Config()) || record.Public != source.link.regional.record.Public || record.HomeAccount != source.link.home.record.Public.CellAccountNKey || source.link.homeLink != nil && record.Signer != source.link.homeLink.record.Signer {
		return bootstrapmaterial.Record{}, ErrMaterialSource
	}
	if err := source.validateLedger(record.Record); err != nil {
		return bootstrapmaterial.Record{}, err
	}
	return record.Record, nil
}

func (source *ColdStartMaterial) validatePublication(publication bootstrapmaterial.Publication, journal []byte) error {
	if source.link != nil {
		return bootstrapmaterial.ValidateLinkPublication(source.directory, publication, journal, time.Now())
	}
	return bootstrapmaterial.ValidatePublication(source.directory, publication, journal)
}

func (link *LinkSource) Record() bootstrapmaterial.LinkRecord {
	if link == nil {
		return bootstrapmaterial.LinkRecord{}
	}
	record := link.record
	record.Record = cloneRecord(record.Record)
	return record
}

func (link *LinkSource) Provision(ctx context.Context, target bootstrapmaterial.VaultTarget, management bootstrapmaterial.VaultClient, bundles bootstrapmaterial.BundleClient, now time.Time) (bootstrapmaterial.Publication, error) {
	if link == nil || link.source == nil {
		return bootstrapmaterial.Publication{}, ErrMaterialSource
	}
	return link.source.Provision(ctx, target, management, bundles, now)
}

type VerifiedLinkMaterial struct {
	material VerifiedColdStartMaterial
	record   bootstrapmaterial.LinkRecord
}

func (link *LinkSource) InstallMaterial(ctx context.Context) (VerifiedLinkMaterial, error) {
	if link == nil || link.source == nil {
		return VerifiedLinkMaterial{}, ErrMaterialSource
	}
	material, err := link.source.InstallMaterial(ctx)
	if err != nil {
		return VerifiedLinkMaterial{}, err
	}
	return VerifiedLinkMaterial{material: material, record: link.Record()}, nil
}
func (verified VerifiedLinkMaterial) IsVerified() bool { return verified.material.IsVerified() }
func (verified VerifiedLinkMaterial) Record() bootstrapmaterial.LinkRecord {
	record := verified.record
	record.Record = cloneRecord(record.Record)
	return record
}
func (verified VerifiedLinkMaterial) Publication() bootstrapmaterial.Publication {
	return verified.material.Publication()
}
func (verified VerifiedLinkMaterial) Grant() region.VerifiedBootstrapMaterial {
	return verified.material.Grant()
}
func (verified VerifiedLinkMaterial) VerifyCurrent(ctx context.Context) error {
	if err := verified.material.VerifyCurrent(ctx); err != nil {
		return err
	}
	return verified.material.source.link.verify(ctx)
}
