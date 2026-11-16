package bootstrapmaterial

import "slices"

// OriginalPublicationSecretNames derives only the closed admission-material
// DATA roster; it authenticates no actor, inventory or publication authority.
func OriginalPublicationSecretNames(cfg Config) ([]string, error) {
	if cfg.Validate() != nil {
		return nil, ErrMaterial
	}
	names := append(expectedNames(), memberCANames[:]...)
	for _, slot := range cfg.Slots {
		names = append(names, slot.Name+"-admission.key")
	}
	secrets := make([]string, 0, len(names))
	for _, name := range names {
		purpose, slot := classify(name)
		if purpose == "" {
			return nil, ErrMaterial
		}
		if purpose != "owner-only" {
			secrets = append(secrets, secretName(cfg, File{Name: name, Purpose: purpose, Slot: slot}))
		}
	}
	slices.Sort(secrets)
	return secrets, nil
}
