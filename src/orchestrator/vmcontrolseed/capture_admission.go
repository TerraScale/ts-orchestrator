package vmcontrolseed

import (
	"bytes"
	"errors"
	"reflect"

	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
)

// ValidatePreliminaryCapture refuses to reuse an initial admission under a
// changed source capability declaration. It never regenerates persisted keys.
func (m Material) ValidatePreliminaryCapture(declaration *PreliminaryCaptureDeclaration) error {
	bad := errors.New("vmcontrolseed: initial source capability differs from requested declaration")
	if declaration != nil {
		if err := declaration.Validate(); err != nil {
			return err
		}
	}
	config, err := initialgrant.ParseConfig([]byte(m.Settings))
	if err != nil {
		return err
	}
	capture := config.PreliminaryCapture
	if !m.Selected || declaration == nil {
		if capture != nil {
			return bad
		}
		return nil
	}
	if capture == nil || capture.MaxSnapshotBytes != declaration.MaxSnapshotBytes || capture.MaxTotalBytes != declaration.MaxTotalBytes {
		return bad
	}
	if declaration.Publication == nil {
		if capture.Publication != nil {
			return bad
		}
		return nil
	}
	if capture.Publication == nil || !reflect.DeepEqual(capture.Publication.Identity, declaration.Publication.Identity) || !bytes.Equal(m.Files[PublicationQualificationKeyPath], declaration.Publication.qualificationPrivateKey) {
		return bad
	}
	return nil
}
