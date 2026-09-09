// Package byokauthority owns customer key operations for admitted BYOK
// databases. It uses only an explicitly configured web identity token and
// role; the process environment is never consulted for credentials.
package byokauthority

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
)

var ErrUnavailable = errors.New("byokauthority: customer key unavailable")

type Binding struct {
	Environment string
	TenantID    string
	ProjectID   string
	DatabaseID  string
	KeyVersion  string
	Region      string
	Purpose     string
}

func (b Binding) encryptionContext() map[string]string {
	return map[string]string{
		"terrascale.environment": b.Environment,
		"terrascale.tenant_id":   b.TenantID,
		"terrascale.project_id":  b.ProjectID,
		"terrascale.database_id": b.DatabaseID,
		"terrascale.key_version": b.KeyVersion,
		"terrascale.region":      b.Region,
		"terrascale.purpose":     b.Purpose,
	}
}

type Config struct {
	Region        string
	RoleARN       string
	OIDCTokenFile string
	KeyARN        string
	SessionName   string
	Duration      time.Duration
}

type kmsAPI interface {
	Encrypt(context.Context, *kms.EncryptInput, ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

type Authority struct {
	client kmsAPI
	keyARN string
}

type tokenFile string

func (f tokenFile) GetIdentityToken() ([]byte, error) { return readToken(string(f)) }

func New(ctx context.Context, config Config) (*Authority, error) {
	if ctx == nil || !validConfig(config) {
		return nil, ErrUnavailable
	}
	token, err := readToken(config.OIDCTokenFile)
	if err != nil {
		return nil, err
	}
	clear(token)
	base, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(config.Region), awsconfig.WithCredentialsProvider(aws.AnonymousCredentials{}))
	if err != nil {
		return nil, ErrUnavailable
	}
	stsClient := sts.NewFromConfig(base)
	provider := stscreds.NewWebIdentityRoleProvider(stsClient, config.RoleARN, tokenFile(config.OIDCTokenFile), func(options *stscreds.WebIdentityRoleOptions) {
		if config.SessionName != "" {
			options.RoleSessionName = config.SessionName
		}
		if config.Duration > 0 {
			options.Duration = config.Duration
		}
	})
	base.Credentials = aws.NewCredentialsCache(provider)
	return &Authority{client: kms.NewFromConfig(base), keyARN: config.KeyARN}, nil
}

func newWithClient(client kmsAPI, keyARN string) (*Authority, error) {
	if client == nil || !validARN(keyARN) {
		return nil, ErrUnavailable
	}
	return &Authority{client: client, keyARN: keyARN}, nil
}

func (a *Authority) Wrap(ctx context.Context, binding Binding, plaintext []byte) (string, error) {
	if a == nil || ctx == nil || ctx.Err() != nil || !validBinding(binding) || len(plaintext) != 32 {
		return "", ErrUnavailable
	}
	result, err := a.client.Encrypt(ctx, &kms.EncryptInput{KeyId: aws.String(a.keyARN), Plaintext: plaintext, EncryptionContext: binding.encryptionContext()})
	if err != nil || result == nil || len(result.CiphertextBlob) == 0 {
		return "", ErrUnavailable
	}
	return base64.RawStdEncoding.EncodeToString(result.CiphertextBlob), nil
}

func (a *Authority) Unwrap(ctx context.Context, binding Binding, ciphertext string) (*hostsecrets.DataKey, error) {
	if a == nil || ctx == nil || ctx.Err() != nil || !validBinding(binding) {
		return nil, ErrUnavailable
	}
	blob, err := base64.RawStdEncoding.Strict().DecodeString(ciphertext)
	if err != nil || len(blob) == 0 || len(blob) > 8192 {
		return nil, ErrUnavailable
	}
	result, err := a.client.Decrypt(ctx, &kms.DecryptInput{KeyId: aws.String(a.keyARN), CiphertextBlob: blob, EncryptionContext: binding.encryptionContext()})
	if err != nil || result == nil || len(result.Plaintext) != 32 {
		if result != nil {
			clear(result.Plaintext)
		}
		return nil, ErrUnavailable
	}
	key, err := hostsecrets.NewDataKey()
	if err != nil {
		clear(result.Plaintext)
		return nil, ErrUnavailable
	}
	copy(key.Bytes(), result.Plaintext)
	clear(result.Plaintext)
	return key, nil
}

func validConfig(config Config) bool {
	return validRegion(config.Region) && validARN(config.RoleARN) && validARN(config.KeyARN) && config.SessionName != "" && len(config.SessionName) <= 64 && config.Duration >= 0 && config.Duration <= 3600*time.Second && filepath.IsAbs(config.OIDCTokenFile) && filepath.Clean(config.OIDCTokenFile) == config.OIDCTokenFile
}

func validBinding(binding Binding) bool {
	return binding.Environment != "" && binding.TenantID != "" && binding.ProjectID != "" && binding.DatabaseID != "" && binding.KeyVersion != "" && binding.Region != "" && (binding.Purpose == "data" || binding.Purpose == "backup" || binding.Purpose == "checkpoint")
}

func validRegion(value string) bool {
	if len(value) < 5 || len(value) > 32 {
		return false
	}
	for _, c := range value {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

func validARN(value string) bool {
	return len(value) >= 20 && len(value) <= 2048 && strings.HasPrefix(value, "arn:aws:") && !strings.ContainsAny(value, "\r\n\x00")
}

func readToken(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > 16<<10 {
		return nil, ErrUnavailable
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 || len(data) > 16<<10 || strings.ContainsAny(string(data), "\x00\r\n") {
		clear(data)
		return nil, ErrUnavailable
	}
	return data, nil
}

func clear(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
