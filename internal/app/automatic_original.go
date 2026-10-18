package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/rootfoundation"
)

func runAutomaticOriginalSeed(ctx context.Context) error {
	archive, err := rootfoundation.OpenOriginalStartupArchive(ctx)
	if err != nil {
		return err
	}
	template, record, link, err := archive.OriginalStartup(ctx, time.Now().UTC())
	if err != nil {
		return err
	}
	if _, err := template.OriginalLaunch(); err != nil {
		return err
	}
	references, err := archive.OriginalStartupReferences(ctx)
	if err != nil {
		return err
	}
	references, err = originalStartupLinkReferences(template.StartupIdentity().Cell, references, link.References())
	if err != nil {
		return err
	}
	var linkRecord bootstrapmaterial.LinkRecord
	if err := protocol.DecodeStrict(link.MaterialRecord(), &linkRecord, 48<<10); err != nil {
		return err
	}
	configs := make(map[string][]byte, len(template.StartupIdentity().ControllerSlots))
	for _, slot := range template.StartupIdentity().ControllerSlots {
		manifest, err := template.ManifestFor(slot, references)
		if err != nil {
			return err
		}
		manifest, err = automaticControllerConfigWithLink(manifest, record, linkRecord, template.Template().TrustedSigners, time.Now().UTC())
		if err != nil {
			return err
		}
		configs[slot] = bytes.Clone(manifest.ControllerConfig)
	}
	authority, err := archive.BindOriginalStartup(ctx, template, link, configs, time.Now().UTC())
	if err != nil {
		return err
	}
	if authority.Manifest().Slot != template.Template().SeedSlot || !bytes.Equal(authority.Manifest().ControllerConfig, configs[template.Template().SeedSlot]) {
		return errors.New("original seed authority differs from its durable house-rendered configuration")
	}
	if _, err := archive.PrepareOriginalSeed(ctx, authority); err != nil {
		return err
	}
	return runAutomaticOriginalController(ctx, authority)
}

func runAutomaticOriginalController(ctx context.Context, authority bootstrap.DerivedStartupAuthority) error {
	if _, err := authority.OriginalLaunch(); err != nil {
		return err
	}
	if err := authority.VerifyCurrent(ctx, time.Now().UTC()); err != nil {
		return err
	}
	if err := validateAutomaticAuthorityRendering(authority); err != nil {
		return err
	}
	if err := bootstrapstart.InstallOriginalLaunchMaterial(ctx, authority); err != nil {
		return err
	}
	if err := installAutomaticControllerFiles(ctx, authority); err != nil {
		return err
	}
	config, err := LoadConfig(filepath.Join(controllerConfigDirectory, controllerConfigFilename))
	if err != nil {
		return err
	}
	return bootstrapController(ctx, config)
}

func originalStartupLinkReferences(cell oci.Region, references, link []bootstrap.SecretReference) ([]bootstrap.SecretReference, error) {
	out := slices.Clone(references)
	for _, reference := range link {
		index := slices.IndexFunc(out, func(existing bootstrap.SecretReference) bool {
			return existing.TargetFile == reference.TargetFile
		})
		if index < 0 {
			out = append(out, reference)
			continue
		}
		if cell != oci.RegionGRU || reference.TargetFile != "cell.jwt" {
			return nil, errors.New("original startup Link repeats a regional material output")
		}
		out[index] = reference
	}
	return out, nil
}

func loadInstalledOriginalStartupAuthority(ctx context.Context, local automaticFoundation, authority bootstrap.DerivedStartupAuthority) (bootstrap.DerivedStartupAuthority, error) {
	if _, err := authority.OriginalLaunch(); err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	if authority.Template().OriginAnchor().Digest() != local.anchor.Digest() || authority.Manifest().Cell != local.baked.Identity.Cell ||
		authority.Manifest().DeploymentID != local.baked.Identity.DeploymentID || authority.Manifest().Environment != local.baked.Identity.Environment {
		return bootstrap.DerivedStartupAuthority{}, errors.New("installed original startup proof differs from its authenticated origin and regional identity")
	}
	for _, file := range []bootstrap.ControllerConfigFile{
		{Name: automaticStartupGrantFilename, Bytes: authority.GrantWire()},
		{Name: automaticStartupAuthorityFilename, Bytes: authority.Wire()},
	} {
		wire, err := readInstalledControllerFile(controllerConfigDirectory, file.Name, 0, 0, 0o444, len(file.Bytes))
		if err != nil || !bytes.Equal(wire, file.Bytes) {
			return bootstrap.DerivedStartupAuthority{}, fmt.Errorf("installed original startup file %s differs from current source: %w", file.Name, errors.Join(err, bootstrap.ErrManifestInvalid))
		}
	}
	if err := authority.VerifyCurrent(ctx, time.Now().UTC()); err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	if err := validateAutomaticAuthorityRendering(authority); err != nil {
		return bootstrap.DerivedStartupAuthority{}, err
	}
	return authority, nil
}
