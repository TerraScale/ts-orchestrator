//go:build linux

package managedmaterial

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/v2"
)

const ()

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

func (service PreparationService) validateNativeInitial(ctx context.Context,
	spec InitialSpec, bundle InitialBundle,
) error {
	if service.NativeValidator == nil || !lowerHexDigest(service.NativeVerifierSHA256) {
		return ErrMaterialConflict
	}
	input, err := nativeInitialInput(spec, bundle)
	if err != nil {
		return err
	}
	return service.NativeValidator.ValidateManagedMaterial(ctx, input, service.NativeVerifierSHA256)
}

func nativeInitialInput(spec InitialSpec, bundle InitialBundle) (NativeMaterialInput, error) {
	if validateBundleForSpec(spec, bundle) != nil {
		return NativeMaterialInput{}, ErrMaterialConflict
	}
	first := bundle.Members[0].Files["signed-v2-s3-config.json"].Contents
	second := bundle.Members[1].Files["signed-v2-s3-config.json"].Contents
	if len(first) == 0 || !bytes.Equal(first, second) {
		return NativeMaterialInput{}, ErrMaterialConflict
	}
	targetDigest, err := spec.LiveS3.Digest()
	if err != nil {
		return NativeMaterialInput{}, ErrMaterialConflict
	}
	input := NativeMaterialInput{
		Certificate: bundle.Authority.Certificate, TrustedKey: bundle.Authority.TrustedKey,
		SignedV2S3Config: first, Scope: spec.Scope,
		MemberIDs:               []string{spec.Members[0].MemberID, spec.Members[1].MemberID},
		ExpectedConfigurationID: bundle.Authority.ConfigurationID,
		ExpectedS3TargetDigest:  targetDigest,
	}
	if spec.Backup != nil {
		input.BackupManagedManifest = bundle.Members[0].Files[backupManifestName].Contents
		input.BackupS3Config = bundle.Members[0].Files[backupConfigName].Contents
		input.ExpectedBackupTargetDigest, err = spec.Backup.Target.Digest()
		if err != nil {
			return NativeMaterialInput{}, ErrMaterialConflict
		}
		var envelope backupManifestEnvelope
		if err := json.Unmarshal(input.BackupManagedManifest, &envelope, json.RejectUnknownMembers(true)); err != nil {
			return NativeMaterialInput{}, ErrMaterialConflict
		}
		payloadBytes, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
		if err != nil {
			return NativeMaterialInput{}, ErrMaterialConflict
		}
		var payload BackupManifestPayload
		if err := json.Unmarshal(payloadBytes, &payload, json.RejectUnknownMembers(true)); err != nil {
			return NativeMaterialInput{}, ErrMaterialConflict
		}
		input.ExpectedBackupSet = payload.BackupSet
	}
	return input, nil
}
