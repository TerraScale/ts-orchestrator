package materialsource

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/region"
)

type linkInputs struct {
	recipient                                  *bootstrap.LinkRecipient
	recipientGrant                             region.VerifiedBootstrapMaterial
	regional, home                             *ColdStartMaterial
	homeLink                                   *LinkSource
	regionalDigest, homeDigest, homeLinkDigest string
}

// LinkSource retains the recovered founder-only Link signer and its durable publication.
type LinkSource struct {
	source *ColdStartMaterial
	record bootstrapmaterial.LinkRecord
}

// ResolveLinkSource recovers the home Link signer from its original home roots.
// Regional recipients use IssueRegionalLink with sealed public inventory.
func ResolveLinkSource(ctx context.Context, regional, home *ColdStartMaterial, homeLink *LinkSource, objects bootstrapstart.FounderSelectionObjectWriter, management bootstrapmaterial.VaultClient, bundles EscrowClient, directory string, now time.Time) (*LinkSource, error) {
	if regional == nil || regional.actor == nil || home == nil || regional != home || homeLink != nil || regional.grant.Config().Cell != natscell.LinkHome || regional.kind != "" || home.kind != "" || objects == nil || management == nil || bundles == nil || now.IsZero() || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, ErrMaterialSource
	}
	inputs := &linkInputs{regional: regional, home: home, homeLink: homeLink, regionalDigest: digestWire(regional.archive.Files["material.json"]), homeDigest: digestWire(home.archive.Files["material.json"])}
	if overlappingSourceDirectories(directory, home.directory) {
		return nil, ErrMaterialSource
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
	source := &ColdStartMaterial{grant: grant, actor: regional.actor, objects: objects, directory: directory, kind: "link", binding: binding, link: inputs, secretName: "ts-bootstrap-source-link-" + hex.EncodeToString(scope[:16]), key: grant.StorageDomain().Prefix + "/bootstrap/v2/material-source/link-" + hex.EncodeToString(scope[:]) + ".json"}
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
	if inputs.recipient != nil {
		return inputs.verifyRecipient(ctx)
	}
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
	if regional != home || cfg.Cell != natscell.LinkHome || inputs.homeLink != nil || inputs.regionalDigest != inputs.homeDigest || !reflect.DeepEqual(cfg, homeCfg) {
		return ErrMaterialSource
	}
	return nil
}

func (source *ColdStartMaterial) verifySource(ctx context.Context) error {
	if source == nil || !source.grant.IsVerified() || !time.Now().Before(source.grant.ExpiresAt()) || ctx.Err() != nil {
		return ErrMaterialSource
	}
	if err := source.guard(ctx); err != nil {
		return fmt.Errorf("%w: source guard: %w", ErrMaterialSource, err)
	}
	if source.link != nil {
		if err := source.link.verify(ctx); err != nil {
			return err
		}
	}
	state, _, err := source.read(ctx)
	defer clear(state.Journal)
	if err != nil {
		return fmt.Errorf("%w: source read: %w", ErrMaterialSource, err)
	}
	if state.Reference != source.state.Reference || state.Reference.SecretOCID == "" {
		return fmt.Errorf("%w: source escrow reference changed", ErrMaterialSource)
	}
	if _, err := source.loadRecord(source.directory); err != nil {
		return err
	}
	for name, expected := range source.archive.Files {
		actual, err := os.ReadFile(filepath.Join(source.directory, name))
		same := err == nil && bytes.Equal(actual, expected)
		clear(actual)
		if !same {
			return fmt.Errorf("%w: restored source file %s differs", ErrMaterialSource, name)
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
	regional, err := source.link.regionalRecord()
	if err != nil {
		return bootstrapmaterial.Record{}, err
	}
	record, err := bootstrapmaterial.LoadLink(directory, time.Now())
	if err != nil {
		return bootstrapmaterial.Record{}, errors.Join(ErrMaterialSource, err)
	}
	if record.SourceSHA256 != source.link.regionalDigest || record.HomeSHA256 != source.link.homeDigest || record.HomeLinkSHA256 != source.link.homeLinkDigest || !reflect.DeepEqual(record.Config, source.grant.Config()) || record.Public != regional.Public || record.HomeAccount != source.link.home.record.Public.CellAccountNKey || source.link.homeLink != nil && record.Signer != source.link.homeLink.record.Signer {
		return bootstrapmaterial.Record{}, fmt.Errorf("%w: Link record differs from source binding", ErrMaterialSource)
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
	return verified.material.VerifyCurrent(ctx)
}

func overlappingSourceDirectories(first, second string) bool {
	return first == second || strings.HasPrefix(first, second+string(filepath.Separator)) || strings.HasPrefix(second, first+string(filepath.Separator))
}
