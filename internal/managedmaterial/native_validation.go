//go:build linux

package managedmaterial

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"golang.org/x/sys/unix"
)

const packagedNativeVerifierPath = "/usr/local/lib/terrascale-orchestrator/managed-material/terrabase-server"

const (
	maxNativeInputBytes  = 8 << 20
	maxNativeOutputBytes = 4 << 10
	maxNativeBinaryBytes = 128 << 20
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

// PackagedNativeMaterialValidator executes only the opened, digest-pinned,
// root-owned TerraBase binary shipped in the accepted controller image.
type PackagedNativeMaterialValidator struct{}

type nativeValidationRequest struct {
	Version               uint64              `json:"version"`
	Mode                  string              `json:"mode"`
	AuthorityCertificate  string              `json:"authority_certificate"`
	TrustedKey            string              `json:"trusted_key"`
	SignedV2S3Config      string              `json:"signed_v2_s3_config"`
	BackupManagedManifest string              `json:"backup_managed_manifest,omitempty"`
	BackupS3Config        string              `json:"backup_s3_config,omitempty"`
	Expected              nativeExpectedScope `json:"expected"`
}

type nativeExpectedScope struct {
	ClusterID                   string   `json:"cluster_id"`
	TenantID                    string   `json:"tenant_id"`
	DatabaseID                  string   `json:"database_id"`
	ShardID                     uint64   `json:"shard_id"`
	Epoch                       uint64   `json:"epoch"`
	MemberIDs                   []string `json:"member_ids"`
	ConfigurationID             string   `json:"configuration_id"`
	CertificateSHA256           string   `json:"certificate_sha256"`
	TrustedKeySHA256            string   `json:"trusted_key_sha256"`
	SignedV2S3ConfigSHA256      string   `json:"signed_v2_s3_config_sha256"`
	S3TargetDigest              string   `json:"s3_target_digest"`
	BackupManagedManifestSHA256 string   `json:"backup_managed_manifest_sha256,omitempty"`
	BackupS3ConfigSHA256        string   `json:"backup_s3_config_sha256,omitempty"`
	BackupTargetDigest          string   `json:"backup_target_digest,omitempty"`
	BackupSet                   string   `json:"backup_set,omitempty"`
}

type nativeValidationVerdict struct {
	Version                     uint64   `json:"version"`
	Mode                        string   `json:"mode"`
	CertificateSHA256           string   `json:"certificate_sha256"`
	TrustedKeySHA256            string   `json:"trusted_key_sha256"`
	ConfigurationID             string   `json:"configuration_id"`
	Epoch                       uint64   `json:"epoch"`
	SignedV2S3ConfigSHA256      string   `json:"signed_v2_s3_config_sha256"`
	S3TargetDigest              string   `json:"s3_target_digest"`
	BackupManagedManifestSHA256 string   `json:"backup_managed_manifest_sha256,omitempty"`
	BackupS3ConfigSHA256        string   `json:"backup_s3_config_sha256,omitempty"`
	BackupTargetDigest          string   `json:"backup_target_digest,omitempty"`
	BackupSet                   string   `json:"backup_set,omitempty"`
	ClusterID                   string   `json:"cluster_id"`
	TenantID                    string   `json:"tenant_id"`
	DatabaseID                  string   `json:"database_id"`
	ShardID                     uint64   `json:"shard_id"`
	MemberIDs                   []string `json:"member_ids"`
	NativeBuildID               string   `json:"native_build_id"`
}

func (PackagedNativeMaterialValidator) ValidateManagedMaterial(ctx context.Context,
	input NativeMaterialInput, pinnedSHA256 string,
) error {
	if ctx == nil || !lowerHexDigest(pinnedSHA256) {
		return errors.New("native material validation input is incomplete")
	}
	wire, err := encodeNativeValidationRequest(input)
	if err != nil {
		return err
	}
	file, err := openPackagedNativeVerifier()
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("hash native verifier: %w", err)
	}
	if hex.EncodeToString(hash.Sum(nil)) != pinnedSHA256 {
		return errors.New("native verifier differs from signed digest")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	runCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(runCtx, "/proc/self/fd/3", "validate-managed-material-v1")
	command.ExtraFiles = []*os.File{file}
	command.Stdin = bytes.NewReader(wire)
	command.Env = []string{"PATH=/usr/bin:/bin"}
	command.Dir = "/"
	command.WaitDelay = time.Second
	stdout := limitedNativeOutput{limit: maxNativeOutputBytes}
	stderr := limitedNativeOutput{limit: maxNativeOutputBytes}
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		if runCtx.Err() != nil {
			return fmt.Errorf("native verifier timed out: %w", runCtx.Err())
		}
		return fmt.Errorf("native verifier rejected managed material: %w", err)
	}
	if stdout.overflow || stderr.overflow || stdout.Len() == 0 {
		return errors.New("native verifier output exceeds its bound")
	}
	var verdict nativeValidationVerdict
	if err := json.Unmarshal(stdout.Bytes(), &verdict, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("decode native verifier verdict: %w", err)
	}
	if verdict.Version != 1 || verdict.Mode != "alpha_object_durable" ||
		verdict.CertificateSHA256 != sha256Hex(input.Certificate) ||
		verdict.TrustedKeySHA256 != sha256Hex(input.TrustedKey) ||
		verdict.SignedV2S3ConfigSHA256 != sha256Hex(input.SignedV2S3Config) ||
		verdict.S3TargetDigest != input.ExpectedS3TargetDigest ||
		verdict.BackupManagedManifestSHA256 != optionalNativeDigest(input.BackupManagedManifest) ||
		verdict.BackupS3ConfigSHA256 != optionalNativeDigest(input.BackupS3Config) ||
		verdict.BackupTargetDigest != input.ExpectedBackupTargetDigest ||
		verdict.BackupSet != input.ExpectedBackupSet ||
		verdict.ConfigurationID != input.ExpectedConfigurationID ||
		verdict.ClusterID != input.Scope.ClusterID || verdict.TenantID != input.Scope.TenantID ||
		verdict.DatabaseID != input.Scope.DatabaseID || verdict.ShardID != input.Scope.ShardID ||
		verdict.Epoch != input.Scope.Epoch ||
		!slices.Equal(verdict.MemberIDs, input.MemberIDs) ||
		strings.TrimSpace(verdict.NativeBuildID) == "" {
		return errors.New("native verifier verdict differs from prepared material")
	}
	return nil
}

func encodeNativeValidationRequest(input NativeMaterialInput) ([]byte, error) {
	if !lowerHexDigest(input.ExpectedConfigurationID) || !lowerHexDigest(input.ExpectedS3TargetDigest) ||
		len(input.Certificate) == 0 || len(input.TrustedKey) != 32 ||
		len(input.SignedV2S3Config) == 0 || len(input.SignedV2S3Config) > 16<<10 || input.Scope.Epoch == 0 ||
		len(input.MemberIDs) != 2 ||
		!slices.IsSorted(input.MemberIDs) {
		return nil, errors.New("native material validation input is incomplete")
	}
	backupPresent := len(input.BackupManagedManifest) > 0
	if backupPresent {
		set, err := entityid.Parse(input.ExpectedBackupSet)
		if len(input.BackupManagedManifest) > 16<<10 || len(input.BackupS3Config) == 0 ||
			len(input.BackupS3Config) > 16<<10 || !lowerHexDigest(input.ExpectedBackupTargetDigest) ||
			err != nil || len(set) != 16 || !entityid.Valid(input.ExpectedBackupSet) ||
			bytes.Equal(set[:], make([]byte, 16)) ||
			input.ExpectedBackupTargetDigest == input.ExpectedS3TargetDigest {
			return nil, errors.New("native backup material validation input is incomplete")
		}
	} else if len(input.BackupS3Config) != 0 || input.ExpectedBackupTargetDigest != "" ||
		input.ExpectedBackupSet != "" {
		return nil, errors.New("partial native backup validation input")
	}
	for index := 1; index < len(input.MemberIDs); index++ {
		if input.MemberIDs[index] == input.MemberIDs[index-1] {
			return nil, errors.New("native material member IDs repeat")
		}
	}
	request := nativeValidationRequest{Version: 1, Mode: "alpha_object_durable",
		AuthorityCertificate:  base64.StdEncoding.EncodeToString(input.Certificate),
		TrustedKey:            base64.StdEncoding.EncodeToString(input.TrustedKey),
		SignedV2S3Config:      base64.StdEncoding.EncodeToString(input.SignedV2S3Config),
		BackupManagedManifest: base64.StdEncoding.EncodeToString(input.BackupManagedManifest),
		BackupS3Config:        base64.StdEncoding.EncodeToString(input.BackupS3Config),
		Expected: nativeExpectedScope{
			ClusterID: input.Scope.ClusterID, TenantID: input.Scope.TenantID,
			DatabaseID: input.Scope.DatabaseID, ShardID: input.Scope.ShardID,
			Epoch: input.Scope.Epoch, MemberIDs: slices.Clone(input.MemberIDs),
			ConfigurationID:             input.ExpectedConfigurationID,
			CertificateSHA256:           sha256Hex(input.Certificate),
			TrustedKeySHA256:            sha256Hex(input.TrustedKey),
			SignedV2S3ConfigSHA256:      sha256Hex(input.SignedV2S3Config),
			S3TargetDigest:              input.ExpectedS3TargetDigest,
			BackupManagedManifestSHA256: optionalNativeDigest(input.BackupManagedManifest),
			BackupS3ConfigSHA256:        optionalNativeDigest(input.BackupS3Config),
			BackupTargetDigest:          input.ExpectedBackupTargetDigest,
			BackupSet:                   input.ExpectedBackupSet,
		},
	}
	wire, err := json.Marshal(request)
	if err != nil || len(wire) == 0 || len(wire) > maxNativeInputBytes {
		return nil, errors.New("native material validation request exceeds its bound")
	}
	return wire, nil
}

func optionalNativeDigest(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	return sha256Hex(data)
}

type limitedNativeOutput struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (output *limitedNativeOutput) Write(data []byte) (int, error) {
	if output.Len()+len(data) > output.limit {
		output.overflow = true
		return 0, errors.New("native verifier output limit exceeded")
	}
	return output.Buffer.Write(data)
}

func openPackagedNativeVerifier() (*os.File, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(packagedNativeVerifierPath, "/"), "/")
	for _, component := range parts[:len(parts)-1] {
		next, openErr := unix.Openat(fd, component,
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if openErr != nil {
			return nil, fmt.Errorf("open native verifier directory: %w", openErr)
		}
		fd = next
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
			stat.Uid != 0 || stat.Mode&0o022 != 0 {
			unix.Close(fd)
			return nil, errors.New("native verifier directory is not root-owned and immutable")
		}
	}
	fileFD, err := unix.Openat(fd, parts[len(parts)-1], unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	unix.Close(fd)
	if err != nil {
		return nil, fmt.Errorf("open packaged native verifier: %w", err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fileFD, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Uid != 0 || stat.Mode&0o022 != 0 || stat.Mode&0o111 == 0 ||
		stat.Nlink != 1 || stat.Size <= 0 || stat.Size > maxNativeBinaryBytes {
		unix.Close(fileFD)
		return nil, errors.New("packaged native verifier is not a bounded root-owned executable")
	}
	return os.NewFile(uintptr(fileFD), packagedNativeVerifierPath), nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
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
