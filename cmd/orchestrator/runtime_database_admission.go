package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"google.golang.org/protobuf/proto"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	pb "terrascale.tech/orchestrator/src/orchestrator/tbep/wire/terrabase/v1"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/byokstatus"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
	"terrascale.tech/orchestrator/src/orchestrator/keylease"
	"terrascale.tech/orchestrator/src/orchestrator/placementpublisher"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

type productionDatabaseFileConfig struct {
	NativeReceiptKeys     map[string]databaseBranchKeyFile      `json:"nativeReceiptKeys"`
	ReadinessKeys         map[string]productionReadinessKeyFile `json:"readinessKeys"`
	Inventory             databaseInventoryFileConfig           `json:"inventory"`
	BranchRestoreKeys     map[string]databaseBranchKeyFile      `json:"branchRestoreKeys"`
	Environment           string                                `json:"environment"`
	Cluster               string                                `json:"cluster"`
	CatalogPath           string                                `json:"catalogPath"`
	Authorization         databaseAuthorizationFile             `json:"authorization"`
	BYOK                  byokPolicyFileConfig                  `json:"byok"`
	BYOKStatus            byokStatusFileConfig                  `json:"byokStatus"`
	DeletionAuthorization databaseAuthorizationFile             `json:"deletionAuthorization"`
	DeletionClaim         databaseDeletionClaimConfig           `json:"deletionClaim"`
	Regions               []databaseRegionFile                  `json:"regions"`
}
type byokStatusFileConfig struct {
	Endpoint       string `json:"endpoint"`
	ServiceKeyFile string `json:"serviceKeyFile"`
}
type databaseAuthorizationFile struct {
	Endpoint       string `json:"endpoint"`
	ServiceKeyFile string `json:"serviceKeyFile"`
}
type databaseRegionFile struct {
	Region         string           `json:"region"`
	Writer         databaseHostFile `json:"writer"`
	Follower       databaseHostFile `json:"follower"`
	CryptoEndpoint string           `json:"cryptoEndpoint"`
	KEKID          string           `json:"kekId"`
	KEKVersionID   string           `json:"kekVersionId"`
	LeaseSeconds   uint32           `json:"leaseSeconds"`
	NotAfter       time.Time        `json:"notAfter"`
}
type databaseHostFile struct {
	ServerIdentity    string                      `json:"serverIdentity"`
	MemberID          string                      `json:"memberId"`
	LifecycleEndpoint string                      `json:"lifecycleEndpoint"`
	LifecycleIdentity string                      `json:"lifecycleIdentity"`
	LifecycleTLS      placementpublisher.TLSFiles `json:"lifecycleTls"`
}

func validLifecycleEndpoint(value string) bool {
	host, port, err := net.SplitHostPort(value)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || (!ip.IsLoopback() && !ip.IsPrivate()) || port == "" {
		return false
	}
	return true
}

func validLifecycleIdentity(value, environment, cluster string) bool {
	if value == "" || environment == "" || cluster == "" {
		return false
	}
	want := "spiffe://terrascale.tech/" + environment + "/terrabase-member/" + cluster + "/"
	return strings.HasPrefix(value, want) && len(value) > len(want)
}

func validLifecycleTLS(files placementpublisher.TLSFiles) bool {
	for _, value := range []string{files.CertificateFile, files.PrivateKeyFile, files.TrustBundleFile} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return false
		}
	}
	return files.CertificateFile != files.PrivateKeyFile && files.CertificateFile != files.TrustBundleFile && files.PrivateKeyFile != files.TrustBundleFile
}

func resolveProductionDatabase(config productionDatabaseFileConfig, placement productionPlacementConfig, auth productionAuthBootstrapConfig) (productionDatabaseConfig, error) {
	if err := config.Inventory.Validate(); err != nil {
		return productionDatabaseConfig{}, err
	}
	canonicalID := regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	result := productionDatabaseConfig{Inventory: config.Inventory, Environment: config.Environment, Cluster: config.Cluster, CatalogPath: config.CatalogPath}
	result.ProvisionKeys = configuredKeyProvisioner(os.LookupEnv)
	if config.Environment == "" || !canonicalID.MatchString(config.Cluster) || !filepath.IsAbs(config.CatalogPath) || filepath.Clean(config.CatalogPath) != config.CatalogPath || len(config.Regions) < 1 || len(config.Regions) > 3 {
		return result, databaseadmission.ErrInvalid
	}
	seenRegions, seenMembers := map[string]bool{}, map[string]bool{}
	hostRegions := map[string]string{}
	hostMembers := map[string]string{}
	for _, region := range config.Regions {
		ociRegion := map[string]string{"GRU": "sa-saopaulo-1", "SFO": "us-sanjose-1", "FRA": "eu-frankfurt-1"}[region.Region]
		if ociRegion == "" || seenRegions[region.Region] || !hostsecrets.ValidVaultCryptoEndpoint(ociRegion, region.CryptoEndpoint) || !provider.IsOCID(region.KEKID, "key") || !provider.IsOCID(region.KEKVersionID, "keyversion") || region.LeaseSeconds < 1 || region.LeaseSeconds > 1800 || !region.NotAfter.After(time.Now()) {
			return result, databaseadmission.ErrInvalid
		}
		seenRegions[region.Region] = true
		for _, host := range []databaseHostFile{region.Writer, region.Follower} {
			if !canonicalID.MatchString(host.MemberID) || seenMembers[host.MemberID] || host.ServerIdentity != "spiffe://terrascale.tech/"+config.Environment+"/terrabase-member/"+config.Cluster+"/"+host.MemberID || !slices.ContainsFunc(placement.Targets, func(t productionPlacementTarget) bool { return t.ServerIdentity == host.ServerIdentity }) || !validLifecycleEndpoint(host.LifecycleEndpoint) || !validLifecycleIdentity(host.LifecycleIdentity, config.Environment, config.Cluster) || !validLifecycleTLS(host.LifecycleTLS) {
				return result, databaseadmission.ErrInvalid
			}
			seenMembers[host.MemberID] = true
			hostRegions[host.ServerIdentity] = region.Region
			hostMembers[host.ServerIdentity] = host.MemberID
		}
		result.Regions = append(result.Regions, productionDatabaseRegion{Region: region.Region, Writer: productionDatabaseHost{ServerIdentity: region.Writer.ServerIdentity, MemberID: region.Writer.MemberID, LifecycleEndpoint: region.Writer.LifecycleEndpoint, LifecycleIdentity: region.Writer.LifecycleIdentity, LifecycleTLS: region.Writer.LifecycleTLS}, Follower: productionDatabaseHost{ServerIdentity: region.Follower.ServerIdentity, MemberID: region.Follower.MemberID, LifecycleEndpoint: region.Follower.LifecycleEndpoint, LifecycleIdentity: region.Follower.LifecycleIdentity, LifecycleTLS: region.Follower.LifecycleTLS}, Vault: keylease.ProvisionTarget{CryptoEndpoint: region.CryptoEndpoint, KEKID: region.KEKID, KEKVersionID: region.KEKVersionID, LeaseSeconds: region.LeaseSeconds, NotAfter: region.NotAfter}})
	}
	for _, grant := range auth.Grants {
		if grant == nil || grant.Environment != config.Environment || grant.Cluster != config.Cluster {
			return result, databaseadmission.ErrInvalid
		}
		for _, voter := range grant.Voters {
			if voter == nil || !seenMembers[voter.Member] || hostRegions[voter.SpiffeUri] != voter.Region || hostMembers[voter.SpiffeUri] != voter.Member {
				return result, databaseadmission.ErrInvalid
			}
		}
	}
	readinessKeys, err := loadProductionReadinessKeys(config.ReadinessKeys)
	if err != nil {
		return result, err
	}
	if len(readinessKeys) != len(placement.Targets) {
		return result, databaseadmission.ErrInvalid
	}
	for _, target := range placement.Targets {
		if _, ok := readinessKeys[target.ServerIdentity]; !ok {
			return result, databaseadmission.ErrInvalid
		}
	}
	result.ReadinessKeys = readinessKeys
	branchKeys, err := loadDatabaseBranchKeys(config.BranchRestoreKeys, hostMembers)
	if err != nil {
		return result, err
	}
	result.BranchRestoreKeys = branchKeys
	receiptKeys, err := loadDatabaseBranchKeys(config.NativeReceiptKeys, hostMembers)
	if err != nil {
		return result, err
	}
	result.NativeReceiptKeys = receiptKeys
	authorize, err := newDatabaseAuthorizer(config.Authorization)
	if err != nil {
		return result, err
	}
	result.Authorize = authorize
	if config.BYOK.Endpoint != "" || config.BYOK.ServiceKeyFile != "" {
		result.AuthorizeBYOK, err = newBYOKPolicyAuthorizer(config.BYOK)
		if err != nil {
			return result, err
		}
	}
	if config.BYOKStatus.Endpoint != "" || config.BYOKStatus.ServiceKeyFile != "" {
		secret, readErr := bootstrapcredentials.ReadFile(config.BYOKStatus.ServiceKeyFile, true, 4096)
		if readErr != nil {
			return result, readErr
		}
		key := strings.TrimSpace(string(secret))
		clear(secret)
		if len(key) < 32 || len(key) > 2048 || strings.ContainsAny(key, "\r\n\t ") {
			return result, errors.New("BYOK status requires a dedicated service key")
		}
		status, statusErr := byokstatus.New(byokstatus.Config{Endpoint: config.BYOKStatus.Endpoint, ServiceKey: key})
		clear([]byte(key))
		if statusErr != nil {
			return result, statusErr
		}
		result.PublishBYOKStatus = status.Publish
	}
	result.AuthorizeDeletion, err = newDatabaseDeletionAuthorizer(config.DeletionAuthorization)
	if err != nil {
		return result, err
	}
	result.AutomaticDeletionClaim, err = newDatabaseDeletionClaimClient(config.DeletionClaim)
	if err != nil {
		return result, err
	}
	return result, nil
}

func newDatabaseAuthorizer(config databaseAuthorizationFile) (func(context.Context, databaseadmission.Request) error, error) {
	client, key, err := databaseAuthorizationClient(config)
	if err != nil {
		return nil, err
	}
	return databaseAuthorizer(client, config.Endpoint, key), nil
}
func databaseAuthorizationClient(config databaseAuthorizationFile) (*http.Client, string, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.Opaque != "" {
		return nil, "", errors.New("database authorization: explicit HTTPS producer endpoint required")
	}
	secret, err := bootstrapcredentials.ReadFile(config.ServiceKeyFile, true, 4096)
	if err != nil {
		return nil, "", err
	}
	defer clear(secret)
	key := strings.TrimSpace(string(secret))
	if len(key) < 32 || len(key) > 2048 || strings.ContainsAny(key, "\r\n\t ") {
		return nil, "", errors.New("database authorization: dedicated service key required")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return client, key, nil
}
func databaseAuthorizer(client *http.Client, endpoint, key string) func(context.Context, databaseadmission.Request) error {
	return func(ctx context.Context, request databaseadmission.Request) error {
		data, err := json.Marshal(request)
		if err != nil {
			return err
		}
		call, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
		if err != nil {
			return err
		}
		call.Header.Set("Content-Type", "application/json")
		call.Header.Set("x-terrascale-database-admission-key", key)
		response, err := client.Do(call)
		if err != nil {
			return errors.New("database authorization: producer unavailable")
		}
		defer response.Body.Close()
		if response.StatusCode == http.StatusForbidden {
			return databaseadmission.ErrForbidden
		}
		if response.StatusCode != http.StatusOK {
			return errors.New("database authorization: producer unavailable")
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 8193))
		if err != nil || len(body) > 8192 {
			return errors.New("database authorization: invalid response")
		}
		var decision struct {
			Allowed     bool   `json:"allowed"`
			Environment string `json:"environment"`
			TenantID    string `json:"tenant_id"`
			ProjectID   string `json:"project_id"`
			OperationID string `json:"operation_id"`
			ExpiresAt   int64  `json:"expires_at"`
		}
		if json.Unmarshal(body, &decision, json.RejectUnknownMembers(true)) != nil || decision.Environment != request.Environment || decision.TenantID != request.TenantID || decision.ProjectID != request.ProjectID || decision.OperationID != request.OperationID || decision.ExpiresAt <= time.Now().Unix() || decision.ExpiresAt > time.Now().Add(time.Minute).Unix() {
			return errors.New("database authorization: response scope or freshness mismatch")
		}
		if !decision.Allowed {
			return databaseadmission.ErrForbidden
		}
		return nil
	}
}

// Placement's external ingress has no operation argument. It still admits only
// an exact proposal durably allocated by the database admission authority.
func databasePlacementPolicy(journal databaseadmission.Journal) func(context.Context, string, *pb.PlacementStageRequest) error {
	return func(ctx context.Context, host string, proposal *pb.PlacementStageRequest) error {
		records, err := journal.List(ctx)
		if err != nil {
			return err
		}
		data, err := (proto.MarshalOptions{Deterministic: true}).Marshal(proposal)
		if err != nil {
			return err
		}
		for _, record := range records {
			if err := databaseadmission.ValidateRecord(record); err != nil {
				return err
			}
			for _, target := range record.PlacementTargets {
				if target.ServerIdentity == host && bytes.Equal(target.Proposal, data) {
					return nil
				}
			}
		}
		return databaseadmission.ErrForbidden
	}
}
