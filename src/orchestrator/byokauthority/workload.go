package byokauthority

import (
	"context"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type WorkloadScope struct {
	Environment       string
	TenantID          string
	ProjectID         string
	DatabaseID        string
	Role              string
	ExternalID        *string
	Endpoint          string
	Bucket            string
	Region            string
	PlacementRevision string
}

type WorkloadCredentials struct {
	AccessKey            string
	SecretKey            string
	SessionToken         string
	ExpiresAtUnixSeconds uint64
}

type WorkloadConfig struct {
	Region        string
	RoleARN       string
	OIDCTokenFile string
	SessionName   string
	Allowed       WorkloadScope
}

type WorkloadIssuer struct {
	config WorkloadConfig
	issue  func(context.Context) (WorkloadCredentials, error)
}

func NewWorkloadIssuer(ctx context.Context, config WorkloadConfig) (*WorkloadIssuer, error) {
	if ctx == nil || !validWorkloadConfig(config) || config.Allowed.ExternalID != nil {
		return nil, ErrUnavailable
	}
	if _, err := readToken(config.OIDCTokenFile); err != nil {
		return nil, err
	}
	base, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(config.Region), awsconfig.WithCredentialsProvider(aws.AnonymousCredentials{}))
	if err != nil {
		return nil, ErrUnavailable
	}
	provider := stscreds.NewWebIdentityRoleProvider(sts.NewFromConfig(base), config.RoleARN, tokenFile(config.OIDCTokenFile), func(options *stscreds.WebIdentityRoleOptions) {
		options.RoleSessionName = config.SessionName
	})
	credentials := aws.NewCredentialsCache(provider)
	return &WorkloadIssuer{config: config, issue: func(ctx context.Context) (WorkloadCredentials, error) {
		value, err := credentials.Retrieve(ctx)
		if err != nil || !value.HasKeys() || value.Expires.IsZero() {
			return WorkloadCredentials{}, ErrUnavailable
		}
		return WorkloadCredentials{AccessKey: value.AccessKeyID, SecretKey: value.SecretAccessKey, SessionToken: value.SessionToken, ExpiresAtUnixSeconds: uint64(value.Expires.Unix())}, nil
	}}, nil
}

func (i *WorkloadIssuer) Issue(ctx context.Context, scope WorkloadScope) (WorkloadCredentials, error) {
	if i == nil || ctx == nil || ctx.Err() != nil || !sameWorkloadScope(i.config.Allowed, scope) || i.issue == nil {
		return WorkloadCredentials{}, ErrUnavailable
	}
	return i.issue(ctx)
}

func sameWorkloadScope(a, b WorkloadScope) bool {
	return a == b || a.Environment == b.Environment && a.TenantID == b.TenantID && a.ProjectID == b.ProjectID && a.DatabaseID == b.DatabaseID && a.Role == b.Role && a.Endpoint == b.Endpoint && a.Bucket == b.Bucket && a.Region == b.Region && a.PlacementRevision == b.PlacementRevision && (a.ExternalID == nil && b.ExternalID == nil || a.ExternalID != nil && b.ExternalID != nil && *a.ExternalID == *b.ExternalID)
}

func validWorkloadConfig(config WorkloadConfig) bool {
	return validRegion(config.Region) && validARN(config.RoleARN) && config.SessionName != "" && len(config.SessionName) <= 64 && filepath.IsAbs(config.OIDCTokenFile) && filepath.Clean(config.OIDCTokenFile) == config.OIDCTokenFile && validWorkloadScope(config.Allowed)
}

func validWorkloadScope(scope WorkloadScope) bool {
	return scope.Environment != "" && scope.TenantID != "" && scope.ProjectID != "" && scope.DatabaseID != "" && scope.Role != "" && scope.Endpoint != "" && scope.Bucket != "" && scope.Region != "" && scope.PlacementRevision != ""
}
