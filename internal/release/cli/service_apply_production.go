package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

func (c command) uploadServiceQualification(directory string, location releasechannel.Location, roots trust.Keyring, candidate release.ProductionExpectation, qualificationSHA256 string, now time.Time) error {
	directory = filepath.Join(directory, candidate.Cell, candidate.Architecture)
	wire, err := readBoundedRegular(filepath.Join(directory, "production.json"), trust.MaxEnvelopeBytes)
	if err != nil {
		return err
	}
	delegation, err := readBoundedRegular(filepath.Join(directory, "delegation.json"), trust.MaxEnvelopeBytes)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	envelope, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return err
	}
	fingerprint, err := trust.Fingerprint(envelope)
	if err != nil {
		return err
	}
	if fingerprint != qualificationSHA256 {
		return errors.New("service qualification differs from signed claim")
	}
	qualification, err := release.VerifyProductionCurrent(wire, delegation, roots, candidate, now)
	if err != nil {
		return err
	}
	for _, evidence := range qualification.Evidence {
		file, size, digest, err := c.openHashedArtifact(filepath.Join(directory, "..", "..", "objects", evidence.SHA256), release.MaxProductionEvidenceBytes)
		if err != nil {
			return err
		}
		if size != evidence.Bytes || hex.EncodeToString(digest) != evidence.SHA256 {
			file.Close()
			return fmt.Errorf("%w: retained evidence changed", release.ErrProductionQualification)
		}
		err = putImmutable(c.ctx, location.Client, location.Namespace, location.Bucket,
			releasechannel.ServiceQualificationEvidenceObject(candidate.Role, qualificationSHA256, evidence.SHA256), file, size, digest)
		closeErr := file.Close()
		if err := errors.Join(err, closeErr); err != nil {
			return err
		}
	}
	for _, object := range []struct {
		name string
		wire []byte
	}{
		{releasechannel.ServiceQualificationDelegationObject(candidate.Role, qualificationSHA256), delegation},
		{releasechannel.ServiceQualificationObject(candidate.Role, qualificationSHA256), wire},
	} {
		if len(object.wire) == 0 {
			continue
		}
		sum := sha256.Sum256(object.wire)
		if err := putImmutable(c.ctx, location.Client, location.Namespace, location.Bucket, object.name, bytes.NewReader(object.wire), int64(len(object.wire)), sum[:]); err != nil {
			return err
		}
	}
	return nil
}
