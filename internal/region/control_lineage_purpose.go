package region

import "errors"

const RegionalControlLineagePurpose = "regional-control-lineage"

// This shape check grants no authority without the exact verified signed intent.
func (intent FoundationIntent) validateControlLineagePurpose() error {
	if intent.ControlLineagePurpose != RegionalControlLineagePurpose {
		return errors.New("signed foundation intent lacks regional control lineage purpose")
	}
	return nil
}
