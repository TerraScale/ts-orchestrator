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

// OriginalPublicationSecretName binds one closed original file to its exact
// existing Vault name; digest and size stay bound by the authenticated record.
func OriginalPublicationSecretName(cfg Config, file File) (string, error) {
	names, err := OriginalPublicationSecretNames(cfg)
	if err != nil {
		return "", err
	}
	purpose, slot := classify(file.Name)
	if purpose == "" || purpose == "owner-only" || file.Purpose != purpose || file.Slot != slot {
		return "", ErrMaterial
	}
	name := secretName(cfg, file)
	if !slices.Contains(names, name) {
		return "", ErrMaterial
	}
	return name, nil
}
