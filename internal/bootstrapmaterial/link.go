package bootstrapmaterial

import (
	"slices"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
)

// LinkRecord binds immutable leaf credentials to both regional material sources.
// The home-only signer reference is never part of a controller generation.
type LinkRecord struct {
	Record
	SourceSHA256   string `json:"sourceSha256"`
	HomeSHA256     string `json:"homeSha256"`
	HomeLinkSHA256 string `json:"homeLinkSha256,omitempty"`
	HomeAccount    string `json:"homeAccount"`
	Signer         string `json:"signer"`
}

func linkPurpose(name string) (bootstrap.SecretPurpose, string) {
	if name == "issuer-link.seed" {
		return "owner-only", ""
	}
	if name == "link-cell.jwt" {
		return bootstrap.SecretRegionalShared, ""
	}
	if name == "interregion-ca.pem" || name == bootstrap.LinkCredentialsFile {
		return bootstrap.SecretInterRegion, ""
	}
	for _, slot := range []string{"controller-a", "controller-b", "controller-c"} {
		cert, key := bootstrap.InterRegionTLSFiles(slot)
		if name == cert || name == key {
			return bootstrap.SecretInterRegion, slot
		}
	}
	return "", ""
}

// OriginalLinkPublicationSecretNames derives the finite eight-leaf roster before
// generation. The home signer is escrow-only and has no publication name.
func OriginalLinkPublicationSecretNames(cfg Config) ([8]string, error) {
	var result [8]string
	if cfg.Validate() != nil || len(cfg.Slots) != 3 {
		return result, ErrMaterial
	}
	files := []string{"interregion-ca.pem"}
	if cfg.Cell == natscell.LinkHome {
		files = append(files, "link-cell.jwt")
	} else {
		files = append(files, bootstrap.LinkCredentialsFile)
	}
	for _, slot := range cfg.Slots {
		cert, key := bootstrap.InterRegionTLSFiles(slot.Name)
		files = append(files, cert, key)
	}
	slices.Sort(files)
	if len(files) != len(result) {
		return result, ErrMaterial
	}
	for index, name := range files {
		purpose, slot := linkPurpose(name)
		result[index] = secretName(cfg, File{Name: name, Purpose: purpose, Slot: slot})
	}
	return result, nil
}
