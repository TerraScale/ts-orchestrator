package app

import (
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
)

func automaticControllerConfigWithLink(manifest bootstrap.Manifest, record bootstrapmaterial.Record,
	link bootstrapmaterial.LinkRecord, signerWire []byte, now time.Time,
) (bootstrap.Manifest, error) {
	if link.SchemaVersion != 1 || !reflect.DeepEqual(link.Config, record.Config) || link.Public != record.Public ||
		link.IssuedAt.IsZero() || now.Before(link.IssuedAt) || !now.Before(link.ExpiresAt) {
		return bootstrap.Manifest{}, errors.New("startup Link material differs from the regional source")
	}
	signers, err := automaticStartupSigners(signerWire)
	if err != nil {
		return bootstrap.Manifest{}, err
	}
	record.Files = slices.Clone(record.Files)
	for _, file := range link.Files {
		if file.Purpose == "owner-only" {
			continue
		}
		name := file.Name
		if name == "link-cell.jwt" {
			file.Name = "cell.jwt"
		}
		index := slices.IndexFunc(record.Files, func(existing bootstrapmaterial.File) bool {
			return existing.Name == file.Name
		})
		if index >= 0 {
			if name != "link-cell.jwt" {
				return bootstrap.Manifest{}, errors.New("startup Link inventory replaces regional source material")
			}
			record.Files[index] = file
		} else {
			record.Files = append(record.Files, file)
		}
	}
	config, err := ControllerConfigFromRecord(manifest, record, signers[0], now)
	if err != nil {
		return bootstrap.Manifest{}, err
	}
	block, err := bootstrapmaterial.RenderLink(link, manifest.Slot, bootstrapstart.MaterialDirectory)
	if err != nil {
		return bootstrap.Manifest{}, err
	}
	for _, path := range block.Files() {
		if !slices.ContainsFunc(manifest.Secrets, func(ref bootstrap.SecretReference) bool {
			return ref.TargetFile == filepath.Base(path) && ref.Purpose == bootstrap.SecretInterRegion &&
				(ref.Slot == "" || ref.Slot == manifest.Slot)
		}) {
			return bootstrap.Manifest{}, errors.New("startup Link credential is absent from signed material")
		}
	}
	config.NATS.Embedded.Link = &block
	config.Controller.TrustedSigners = signers
	return automaticRenderedControllerConfig(manifest, config)
}
