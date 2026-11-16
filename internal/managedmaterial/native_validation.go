//go:build linux

package managedmaterial

import (
	"context"
)

// NativeMaterialInput contains only public authority and S3 configuration bytes. The
// expected identity comes from the authenticated preparation specification.
type NativeMaterialInput struct {
	Certificate                []byte
	TrustedKey                 []byte
	SignedV2S3Config           []byte
	BackupManagedManifest      []byte
	BackupS3Config             []byte
	Scope                      AuthorityScope
	MemberIDs                  []string
	ExpectedConfigurationID    string
	ExpectedS3TargetDigest     string
	ExpectedBackupTargetDigest string
	ExpectedBackupSet          string
}

type NativeMaterialValidator interface {
	ValidateManagedMaterial(context.Context, NativeMaterialInput, string) error
}
