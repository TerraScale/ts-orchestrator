package materialsource

import "github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"

func (source *ColdStartMaterial) allowNewRegionalSource() error {
	if source.kind != "" {
		return nil
	}
	if _, err := source.grant.SourceRegistration(); err != nil {
		return ErrMaterialSource
	}
	return nil
}

func (source *ColdStartMaterial) validateLedger(record bootstrapmaterial.Record) error {
	if expected, err := source.grant.PinnedLedgerSignerPublicKey(); err == nil {
		if record.Public.LedgerSignerPublicKey != expected {
			return ErrMaterialSource
		}
		return nil
	}
	if _, err := source.grant.SourceRegistration(); err != nil {
		return ErrMaterialSource
	}
	return nil
}
