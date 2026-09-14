package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

func validObjectPart(value string, max int, slash bool) bool {
	if value == "" || len(value) > max || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	return slash || !strings.Contains(value, "/")
}

// OCIEstateSpec is the reviewed, one-time OCI estate consumed by regional
// controllers. Startup reads every identity and refuses malformed scope or
// lifecycle bindings. The orchestrator never creates these resources.
type OCIEstateSpec struct {
	Region                   string                       `json:"region"`
	TenancyID                string                       `json:"tenancyId"`
	ControlCompartmentID     string                       `json:"controlCompartmentId"`
	NetworkCompartmentID     string                       `json:"networkCompartmentId"`
	WorkloadCompartmentID    string                       `json:"workloadCompartmentId"`
	VCNID                    string                       `json:"vcnId"`
	SubnetIDs                []string                     `json:"subnetIds"`
	NetworkSecurityGroupIDs  []string                     `json:"networkSecurityGroupIds"`
	IAMPolicyCompartmentID   string                       `json:"iamPolicyCompartmentId"`
	IAMPolicies              []OCIEstatePolicy            `json:"iamPolicies"`
	DynamicGroupID           string                       `json:"dynamicGroupId"`
	DynamicGroupMatchingRule string                       `json:"dynamicGroupMatchingRule"`
	VaultID                  string                       `json:"vaultId"`
	KeyID                    string                       `json:"keyId"`
	KeyManagementEndpoint    string                       `json:"keyManagementEndpoint"`
	KeyRotationIntervalDays  int                          `json:"keyRotationIntervalDays"`
	ObjectNamespace          string                       `json:"objectNamespace"`
	LedgerBucket             string                       `json:"ledgerBucket"`
	BackupBucket             string                       `json:"backupBucket"`
	LedgerRetentionRules     []OCIEstateRetentionRuleSpec `json:"ledgerRetentionRules"`
	BackupRetentionRules     []OCIEstateRetentionRuleSpec `json:"backupRetentionRules"`
	LedgerLifecycleRules     []OCIEstateLifecycleRuleSpec `json:"ledgerLifecycleRules"`
	BackupLifecycleRules     []OCIEstateLifecycleRuleSpec `json:"backupLifecycleRules"`
}

type OCIEstatePolicy struct {
	ID         string   `json:"id"`
	Statements []string `json:"statements"`
}

type OCIEstateRetentionRuleSpec struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	TimeAmount  int64  `json:"timeAmount"`
	TimeUnit    string `json:"timeUnit"`
	Indefinite  bool   `json:"indefinite"`
}

type OCIEstateLifecycleRuleSpec struct {
	Name              string   `json:"name"`
	Action            string   `json:"action"`
	TimeAmount        int64    `json:"timeAmount"`
	TimeUnit          string   `json:"timeUnit"`
	IsEnabled         bool     `json:"isEnabled"`
	Target            string   `json:"target"`
	InclusionPatterns []string `json:"inclusionPatterns"`
	ExclusionPatterns []string `json:"exclusionPatterns"`
	InclusionPrefixes []string `json:"inclusionPrefixes"`
}

type ociEstateBucket struct {
	Namespace        string `json:"namespace"`
	Name             string `json:"name"`
	CompartmentID    string `json:"compartmentId"`
	PublicAccessType string `json:"publicAccessType"`
	Versioning       string `json:"versioning"`
	KMSKeyID         string `json:"kmsKeyId"`
}

type ociEstateRetentionRule struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Duration    *struct {
		TimeAmount int64  `json:"timeAmount"`
		TimeUnit   string `json:"timeUnit"`
	} `json:"duration"`
}

type ociEstateLifecycleRule struct {
	Name             string `json:"name"`
	Action           string `json:"action"`
	TimeAmount       int64  `json:"timeAmount"`
	TimeUnit         string `json:"timeUnit"`
	IsEnabled        bool   `json:"isEnabled"`
	Target           string `json:"target"`
	ObjectNameFilter *struct {
		InclusionPatterns []string `json:"inclusionPatterns"`
		ExclusionPatterns []string `json:"exclusionPatterns"`
		InclusionPrefixes []string `json:"inclusionPrefixes"`
	} `json:"objectNameFilter"`
}

func LoadOCIEstateSpec(path string) (OCIEstateSpec, error) {
	if !filepath.IsAbs(path) {
		return OCIEstateSpec{}, &errs.Argument{Message: "OCI estate file path must be absolute"}
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return OCIEstateSpec{}, &InvalidDataError{Message: "OCI estate file is unavailable"}
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return OCIEstateSpec{}, &InvalidDataError{Message: "OCI estate file is unavailable"}
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return OCIEstateSpec{}, &InvalidDataError{Message: "OCI estate file is unavailable"}
	}
	stat, statOK := info.Sys().(*syscall.Stat_t)
	if !statOK || stat.Uid != 0 {
		return OCIEstateSpec{}, &InvalidDataError{Message: "OCI estate file is unavailable"}
	}
	body, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || len(body) == 0 || len(body) > 64<<10 {
		return OCIEstateSpec{}, &InvalidDataError{Message: "OCI estate file is invalid"}
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var spec OCIEstateSpec
	if decoder.Decode(&spec) != nil || decoder.Decode(&struct{}{}) != io.EOF || validateOCIEstateSpec(spec) != nil {
		return OCIEstateSpec{}, &InvalidDataError{Message: "OCI estate file is invalid"}
	}
	return spec, nil
}

func validateOCIEstateSpec(spec OCIEstateSpec) error {
	if len(spec.Region) < 1 || len(spec.Region) > 63 || !regionPattern.MatchString(spec.Region) ||
		!isOCID(spec.TenancyID, "tenancy") || !isOCID(spec.ControlCompartmentID, "compartment") ||
		!isOCID(spec.NetworkCompartmentID, "compartment") || !isOCID(spec.WorkloadCompartmentID, "compartment") ||
		spec.ControlCompartmentID == spec.NetworkCompartmentID || spec.ControlCompartmentID == spec.WorkloadCompartmentID || spec.NetworkCompartmentID == spec.WorkloadCompartmentID ||
		!isOCID(spec.VCNID, "vcn") || (!isOCID(spec.IAMPolicyCompartmentID, "compartment") && spec.IAMPolicyCompartmentID != spec.TenancyID) ||
		!isOCID(spec.DynamicGroupID, "dynamicgroup") || !validObjectPart(spec.DynamicGroupMatchingRule, 2048, true) ||
		!isOCID(spec.VaultID, "vault") || !isOCID(spec.KeyID, "key") ||
		!validObjectPart(spec.ObjectNamespace, 128, false) || !validObjectPart(spec.LedgerBucket, 256, false) ||
		!validObjectPart(spec.BackupBucket, 256, false) || spec.LedgerBucket == spec.BackupBucket ||
		len(spec.SubnetIDs) < 1 || len(spec.SubnetIDs) > 16 || len(spec.NetworkSecurityGroupIDs) < 1 || len(spec.NetworkSecurityGroupIDs) > 16 ||
		len(spec.IAMPolicies) == 0 || len(spec.IAMPolicies) > 16 || spec.KeyRotationIntervalDays < 60 || spec.KeyRotationIntervalDays > 365 ||
		validateRetentionRuleSpecs(spec.LedgerRetentionRules) != nil || validateRetentionRuleSpecs(spec.BackupRetentionRules) != nil ||
		validateLifecycleRuleSpecs(spec.LedgerLifecycleRules) != nil || validateLifecycleRuleSpecs(spec.BackupLifecycleRules) != nil {
		return &errs.Argument{Message: "OCI estate specification is incomplete"}
	}
	keyEndpoint, err := NewOCIServiceTransportConfig(OCIServiceVaultManagement, spec.Region, spec.KeyManagementEndpoint)
	if err != nil || keyEndpoint.Endpoint == nil {
		return &errs.Argument{Message: "OCI estate key management endpoint is invalid"}
	}
	policyIDs := make([]string, 0, len(spec.IAMPolicies))
	for _, policy := range spec.IAMPolicies {
		if len(policy.Statements) == 0 || len(policy.Statements) > 32 {
			return &errs.Argument{Message: "OCI estate IAM policy is incomplete"}
		}
		seenStatements := map[string]bool{}
		for _, statement := range policy.Statements {
			if len(statement) < 1 || len(statement) > 1024 || strings.ContainsAny(statement, "\r\n") || seenStatements[statement] {
				return &errs.Argument{Message: "OCI estate IAM policy statement is invalid"}
			}
			seenStatements[statement] = true
		}
		policyIDs = append(policyIDs, policy.ID)
	}
	return validateEstateIDs(spec.SubnetIDs, "subnet", spec.NetworkSecurityGroupIDs, "networksecuritygroup", policyIDs, "policy")
}

func validateRetentionRuleSpecs(rules []OCIEstateRetentionRuleSpec) error {
	if len(rules) == 0 || len(rules) > maximumOCIListResults*maximumOCIPages {
		return &errs.Argument{Message: "OCI estate retention rules are incomplete"}
	}
	seen := map[string]bool{}
	for _, rule := range rules {
		finite := rule.TimeAmount > 0 && (rule.TimeUnit == "DAYS" || rule.TimeUnit == "YEARS") && !rule.Indefinite
		indefinite := rule.Indefinite && rule.TimeAmount == 0 && rule.TimeUnit == ""
		if !validObjectPart(rule.ID, 256, false) || !validObjectPart(rule.DisplayName, 256, true) || (!finite && !indefinite) || seen[rule.ID] {
			return &errs.Argument{Message: "OCI estate retention rule is invalid"}
		}
		seen[rule.ID] = true
	}
	return nil
}

func validateLifecycleRuleSpecs(rules []OCIEstateLifecycleRuleSpec) error {
	if len(rules) == 0 || len(rules) > 1000 {
		return &errs.Argument{Message: "OCI estate lifecycle rules are incomplete"}
	}
	seen := map[string]bool{}
	for _, rule := range rules {
		actionMatchesTarget := (rule.Action == "ABORT") == (rule.Target == "multipart-uploads")
		if !validObjectPart(rule.Name, 256, true) || rule.TimeAmount <= 0 || (rule.TimeUnit != "DAYS" && rule.TimeUnit != "YEARS") ||
			(rule.Action != "ARCHIVE" && rule.Action != "INFREQUENT_ACCESS" && rule.Action != "DELETE" && rule.Action != "ABORT") ||
			(rule.Target != "objects" && rule.Target != "multipart-uploads" && rule.Target != "previous-object-versions") || !actionMatchesTarget || seen[rule.Name] ||
			!validLifecycleFilters(rule.InclusionPatterns) || !validLifecycleFilters(rule.ExclusionPatterns) || !validLifecycleFilters(rule.InclusionPrefixes) {
			return &errs.Argument{Message: "OCI estate lifecycle rule is invalid"}
		}
		seen[rule.Name] = true
	}
	return nil
}

func validLifecycleFilters(values []string) bool {
	if len(values) > 1000 {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !validObjectPart(value, 1024, true) || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}

func validateEstateIDs(groups ...any) error {
	for index := 0; index < len(groups); index += 2 {
		ids := groups[index].([]string)
		kind := groups[index+1].(string)
		seen := map[string]bool{}
		for _, id := range ids {
			if !isOCID(id, kind) || seen[id] {
				return &errs.Argument{Message: "OCI estate specification contains invalid resource identities"}
			}
			seen[id] = true
		}
	}
	return nil
}

// OCIEstateReader is the provider-neutral, read-only verification seam used
// by startup and fake malformed-estate tests.
type OCIEstateReader interface {
	Read(context.Context, OCIService, string) ([]byte, int, error)
	ReadPage(context.Context, OCIService, string, string) ([]byte, int, string, error)
}

type OCIEstateHTTPReader struct {
	Transports map[OCIService]*OCIHTTPTransport
}

func (r *OCIEstateHTTPReader) Read(ctx context.Context, service OCIService, path string) ([]byte, int, error) {
	body, status, _, err := r.ReadPage(ctx, service, path, "")
	return body, status, err
}

func (r *OCIEstateHTTPReader) ReadPage(ctx context.Context, service OCIService, path, page string) ([]byte, int, string, error) {
	if r == nil {
		return nil, 0, "", &InvalidOperationError{Message: "OCI estate reader is unavailable"}
	}
	transport := r.Transports[service]
	if transport == nil {
		return nil, 0, "", &InvalidOperationError{Message: "OCI estate reader is unavailable"}
	}
	requestPath := path
	if page != "" {
		if !validOCIPageToken(page) {
			return nil, 0, "", &InvalidDataError{Message: "OCI estate pagination is invalid"}
		}
		requestPath += "?" + url.Values{"page": {page}}.Encode()
	}
	resp, err := transport.Do(ctx, http.MethodGet, requestPath, nil)
	if err != nil {
		return nil, 0, "", err
	}
	status := resp.StatusCode
	next, nextErr := validatedOCINextPage(resp)
	body, bodyErr := ReadBoundedBody(resp, transport.Config.MaxBodyBytes)
	if nextErr != nil {
		return nil, status, "", nextErr
	}
	return body, status, next, bodyErr
}

func NewOCIEstateHTTPReader(spec OCIEstateSpec) (*OCIEstateHTTPReader, error) {
	if validateOCIEstateSpec(spec) != nil {
		return nil, &errs.Argument{Message: "OCI estate verification credentials are invalid"}
	}
	federation, err := NewInstancePrincipalFederation(spec.Region, spec.TenancyID, nil, nil)
	if err != nil {
		return nil, err
	}
	return newOCIEstateHTTPReaderWithFederation(spec, federation, nil)
}

func newOCIEstateHTTPReaderWithFederation(spec OCIEstateSpec, federation *InstancePrincipalFederation, client *http.Client) (*OCIEstateHTTPReader, error) {
	if validateOCIEstateSpec(spec) != nil || federation == nil || federation.expectedRegion != spec.Region || federation.expectedTenancy != spec.TenancyID {
		return nil, &errs.Argument{Message: "OCI estate verification credentials are invalid"}
	}
	transports := make(map[OCIService]*OCIHTTPTransport, 5)
	for _, service := range []OCIService{OCIServiceCore, OCIServiceIdentity, OCIServiceObjectStorage, OCIServiceVault} {
		host, _ := ociServiceHost(service, spec.Region)
		config, configErr := NewOCIServiceTransportConfig(service, spec.Region, "https://"+host)
		if configErr != nil {
			return nil, configErr
		}
		transport, transportErr := newOCIFederatedInstancePrincipalTransport(config, client, federation)
		if transportErr != nil {
			return nil, transportErr
		}
		transports[service] = transport
	}
	keyConfig, err := NewOCIServiceTransportConfig(OCIServiceVaultManagement, spec.Region, spec.KeyManagementEndpoint)
	if err != nil {
		return nil, err
	}
	keyTransport, err := newOCIFederatedInstancePrincipalTransport(keyConfig, client, federation)
	if err != nil {
		return nil, err
	}
	transports[OCIServiceVaultManagement] = keyTransport
	return &OCIEstateHTTPReader{Transports: transports}, nil
}

func VerifyOCIEstate(ctx context.Context, spec OCIEstateSpec, reader OCIEstateReader) error {
	if ctx == nil || reader == nil || validateOCIEstateSpec(spec) != nil {
		return &errs.Argument{Message: "OCI estate verification request is invalid"}
	}
	for _, compartment := range []string{spec.ControlCompartmentID, spec.NetworkCompartmentID, spec.WorkloadCompartmentID} {
		if err := verifyEstateResource(ctx, reader, OCIServiceIdentity, "/20160918/compartments/"+url.PathEscape(compartment), compartment, spec.TenancyID, "", false); err != nil {
			return err
		}
	}
	if spec.IAMPolicyCompartmentID != spec.TenancyID && spec.IAMPolicyCompartmentID != spec.ControlCompartmentID &&
		spec.IAMPolicyCompartmentID != spec.NetworkCompartmentID && spec.IAMPolicyCompartmentID != spec.WorkloadCompartmentID {
		if err := verifyEstateResource(ctx, reader, OCIServiceIdentity, "/20160918/compartments/"+url.PathEscape(spec.IAMPolicyCompartmentID), spec.IAMPolicyCompartmentID, spec.TenancyID, "", false); err != nil {
			return err
		}
	}
	if err := verifyEstateResource(ctx, reader, OCIServiceCore, "/20160918/vcns/"+url.PathEscape(spec.VCNID), spec.VCNID, spec.NetworkCompartmentID, "", false); err != nil {
		return err
	}
	for _, subnet := range spec.SubnetIDs {
		if err := verifyEstateResource(ctx, reader, OCIServiceCore, "/20160918/subnets/"+url.PathEscape(subnet), subnet, spec.NetworkCompartmentID, spec.VCNID, true); err != nil {
			return err
		}
	}
	for _, nsg := range spec.NetworkSecurityGroupIDs {
		if err := verifyEstateResource(ctx, reader, OCIServiceCore, "/20160918/networkSecurityGroups/"+url.PathEscape(nsg), nsg, spec.NetworkCompartmentID, spec.VCNID, false); err != nil {
			return err
		}
	}
	for _, policy := range spec.IAMPolicies {
		if err := verifyEstatePolicy(ctx, reader, spec.IAMPolicyCompartmentID, policy); err != nil {
			return err
		}
	}
	if err := verifyEstateDynamicGroup(ctx, reader, spec); err != nil {
		return err
	}
	if err := verifyEstateVault(ctx, reader, spec); err != nil {
		return err
	}
	if err := verifyEstateKey(ctx, reader, spec); err != nil {
		return err
	}
	for _, bucket := range []struct {
		name      string
		retention []OCIEstateRetentionRuleSpec
		lifecycle []OCIEstateLifecycleRuleSpec
	}{
		{spec.LedgerBucket, spec.LedgerRetentionRules, spec.LedgerLifecycleRules},
		{spec.BackupBucket, spec.BackupRetentionRules, spec.BackupLifecycleRules},
	} {
		path := "/n/" + url.PathEscape(spec.ObjectNamespace) + "/b/" + url.PathEscape(bucket.name)
		body, status, err := reader.Read(ctx, OCIServiceObjectStorage, path)
		var document ociEstateBucket
		if err != nil || status < 200 || status >= 300 || json.Unmarshal(body, &document) != nil || !validEstateBucket(document, bucket.name, spec) {
			return &InvalidDataError{Message: "OCI estate verification rejected a bucket"}
		}
		if err := verifyEstateRetentionRules(ctx, reader, path, bucket.retention); err != nil {
			return err
		}
		if err := verifyEstateLifecycleRules(ctx, reader, path, bucket.lifecycle); err != nil {
			return err
		}
	}
	return nil
}

func validEstateBucket(document ociEstateBucket, expectedName string, spec OCIEstateSpec) bool {
	return document.Namespace == spec.ObjectNamespace && document.Name == expectedName &&
		document.CompartmentID == spec.ControlCompartmentID && document.PublicAccessType == "NoPublicAccess" &&
		document.Versioning == "Enabled" && document.KMSKeyID == spec.KeyID
}

func verifyEstateRetentionRules(ctx context.Context, reader OCIEstateReader, bucketPath string, expected []OCIEstateRetentionRuleSpec) error {
	path := bucketPath + "/retentionRules"
	seenPages := map[string]bool{"": true}
	seenRules := make(map[string]OCIEstateRetentionRuleSpec)
	page := ""
	for pagesRead := 1; pagesRead <= maximumOCIPages; pagesRead++ {
		body, status, next, err := reader.ReadPage(ctx, OCIServiceObjectStorage, path, page)
		var document struct {
			Items []ociEstateRetentionRule `json:"items"`
		}
		if err != nil || status < 200 || status >= 300 || json.Unmarshal(body, &document) != nil || document.Items == nil ||
			len(document.Items) > maximumOCIListResults || len(seenRules)+len(document.Items) > maximumOCIListResults*maximumOCIPages {
			return &InvalidDataError{Message: "OCI estate verification rejected bucket retention rules"}
		}
		for _, rule := range document.Items {
			if !validObjectPart(rule.ID, 256, false) || !validObjectPart(rule.DisplayName, 256, true) ||
				(rule.Duration != nil && (rule.Duration.TimeAmount <= 0 || (rule.Duration.TimeUnit != "DAYS" && rule.Duration.TimeUnit != "YEARS"))) {
				return &InvalidDataError{Message: "OCI estate verification rejected bucket retention rules"}
			}
			actual := OCIEstateRetentionRuleSpec{ID: rule.ID, DisplayName: rule.DisplayName, Indefinite: rule.Duration == nil}
			if rule.Duration != nil {
				actual.TimeAmount = rule.Duration.TimeAmount
				actual.TimeUnit = rule.Duration.TimeUnit
			}
			if _, duplicate := seenRules[rule.ID]; duplicate {
				return &InvalidDataError{Message: "OCI estate verification rejected bucket retention rules"}
			}
			seenRules[rule.ID] = actual
		}
		if next == "" {
			if !sameRetentionRuleSet(seenRules, expected) {
				return &InvalidDataError{Message: "OCI estate verification rejected bucket retention rules"}
			}
			return nil
		}
		if !validOCIPageToken(next) || pagesRead == maximumOCIPages || seenPages[next] {
			return &InvalidDataError{Message: "OCI estate verification rejected bucket retention rules"}
		}
		seenPages[next] = true
		page = next
	}
	return &InvalidDataError{Message: "OCI estate verification rejected bucket retention rules"}
}

func sameRetentionRuleSet(actual map[string]OCIEstateRetentionRuleSpec, expected []OCIEstateRetentionRuleSpec) bool {
	if len(actual) != len(expected) {
		return false
	}
	for _, rule := range expected {
		if actual[rule.ID] != rule {
			return false
		}
	}
	return true
}

func verifyEstateLifecycleRules(ctx context.Context, reader OCIEstateReader, bucketPath string, expected []OCIEstateLifecycleRuleSpec) error {
	body, status, err := reader.Read(ctx, OCIServiceObjectStorage, bucketPath+"/l")
	var document struct {
		Items []ociEstateLifecycleRule `json:"items"`
	}
	if err != nil || status < 200 || status >= 300 || json.Unmarshal(body, &document) != nil || document.Items == nil || len(document.Items) != len(expected) {
		return &InvalidDataError{Message: "OCI estate verification rejected bucket lifecycle rules"}
	}
	actual := make(map[string]OCIEstateLifecycleRuleSpec, len(document.Items))
	for _, rule := range document.Items {
		converted := OCIEstateLifecycleRuleSpec{Name: rule.Name, Action: rule.Action, TimeAmount: rule.TimeAmount, TimeUnit: rule.TimeUnit, IsEnabled: rule.IsEnabled, Target: rule.Target}
		if rule.ObjectNameFilter != nil {
			converted.InclusionPatterns = append([]string(nil), rule.ObjectNameFilter.InclusionPatterns...)
			converted.ExclusionPatterns = append([]string(nil), rule.ObjectNameFilter.ExclusionPatterns...)
			converted.InclusionPrefixes = append([]string(nil), rule.ObjectNameFilter.InclusionPrefixes...)
		}
		if validateLifecycleRuleSpecs([]OCIEstateLifecycleRuleSpec{converted}) != nil {
			return &InvalidDataError{Message: "OCI estate verification rejected bucket lifecycle rules"}
		}
		if _, duplicate := actual[rule.Name]; duplicate {
			return &InvalidDataError{Message: "OCI estate verification rejected bucket lifecycle rules"}
		}
		actual[rule.Name] = converted
	}
	for _, rule := range expected {
		got, ok := actual[rule.Name]
		if !ok || got.Name != rule.Name || got.Action != rule.Action || got.TimeAmount != rule.TimeAmount || got.TimeUnit != rule.TimeUnit ||
			got.IsEnabled != rule.IsEnabled || got.Target != rule.Target || !sameStringSet(got.InclusionPatterns, rule.InclusionPatterns) ||
			!sameStringSet(got.ExclusionPatterns, rule.ExclusionPatterns) || !sameStringSet(got.InclusionPrefixes, rule.InclusionPrefixes) {
			return &InvalidDataError{Message: "OCI estate verification rejected bucket lifecycle rules"}
		}
	}
	return nil
}

func verifyEstateDynamicGroup(ctx context.Context, reader OCIEstateReader, spec OCIEstateSpec) error {
	body, status, err := reader.Read(ctx, OCIServiceIdentity, "/20160918/dynamicGroups/"+url.PathEscape(spec.DynamicGroupID))
	var document struct {
		ID, CompartmentID, LifecycleState, MatchingRule string
	}
	if err != nil || status < 200 || status >= 300 || json.Unmarshal(body, &document) != nil || document.ID != spec.DynamicGroupID ||
		document.CompartmentID != spec.TenancyID || document.LifecycleState != "ACTIVE" || document.MatchingRule != spec.DynamicGroupMatchingRule {
		return &InvalidDataError{Message: "OCI estate verification rejected the controller dynamic group"}
	}
	return nil
}

func verifyEstateVault(ctx context.Context, reader OCIEstateReader, spec OCIEstateSpec) error {
	body, status, err := reader.Read(ctx, OCIServiceVault, "/20180608/vaults/"+url.PathEscape(spec.VaultID))
	var document struct {
		ID, CompartmentID, LifecycleState, ManagementEndpoint, VaultType string
	}
	if err != nil || status < 200 || status >= 300 || json.Unmarshal(body, &document) != nil || document.ID != spec.VaultID ||
		document.CompartmentID != spec.ControlCompartmentID || document.LifecycleState != "ACTIVE" || document.ManagementEndpoint != spec.KeyManagementEndpoint ||
		document.VaultType != "VIRTUAL_PRIVATE" {
		return &InvalidDataError{Message: "OCI estate verification rejected the Vault"}
	}
	return nil
}

func verifyEstateKey(ctx context.Context, reader OCIEstateReader, spec OCIEstateSpec) error {
	body, status, err := reader.Read(ctx, OCIServiceVaultManagement, "/20180608/keys/"+url.PathEscape(spec.KeyID))
	var document struct {
		ID, CompartmentID, LifecycleState, VaultID, ProtectionMode string
		KeyShape                                                   struct {
			Algorithm string `json:"algorithm"`
			Length    int    `json:"length"`
		} `json:"keyShape"`
		IsAutoRotationEnabled  bool `json:"isAutoRotationEnabled"`
		AutoKeyRotationDetails *struct {
			RotationIntervalInDays int `json:"rotationIntervalInDays"`
		} `json:"autoKeyRotationDetails"`
	}
	if err != nil || status < 200 || status >= 300 || json.Unmarshal(body, &document) != nil || document.ID != spec.KeyID ||
		document.CompartmentID != spec.ControlCompartmentID || document.LifecycleState != "ENABLED" || document.VaultID != spec.VaultID ||
		document.ProtectionMode != "HSM" || document.KeyShape.Algorithm != "AES" || document.KeyShape.Length != 32 ||
		!document.IsAutoRotationEnabled || document.AutoKeyRotationDetails == nil || document.AutoKeyRotationDetails.RotationIntervalInDays != spec.KeyRotationIntervalDays {
		return &InvalidDataError{Message: "OCI estate verification rejected the Vault key"}
	}
	return nil
}

func verifyEstatePolicy(ctx context.Context, reader OCIEstateReader, compartment string, expected OCIEstatePolicy) error {
	body, status, err := reader.Read(ctx, OCIServiceIdentity, "/20160918/policies/"+url.PathEscape(expected.ID))
	var document struct {
		ID, CompartmentID, LifecycleState string
		Statements                        []string
	}
	if err != nil || status < 200 || status >= 300 || json.Unmarshal(body, &document) != nil || document.ID != expected.ID ||
		document.CompartmentID != compartment || document.LifecycleState != "ACTIVE" || !sameStringSet(document.Statements, expected.Statements) {
		return &InvalidDataError{Message: "OCI estate verification rejected a required IAM policy"}
	}
	return nil
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	counts := make(map[string]int, len(left))
	for _, item := range left {
		counts[item]++
	}
	for _, item := range right {
		counts[item]--
		if counts[item] < 0 {
			return false
		}
	}
	return true
}

func verifyEstateResource(ctx context.Context, reader OCIEstateReader, service OCIService, path, id, compartment, vcn string, requirePrivate bool) error {
	body, status, err := reader.Read(ctx, service, path)
	var document struct {
		ID                     string `json:"id"`
		CompartmentID          string `json:"compartmentId"`
		VCNID                  string `json:"vcnId"`
		LifecycleState         string `json:"lifecycleState"`
		ProhibitPublicIPOnVNIC bool   `json:"prohibitPublicIpOnVnic"`
	}
	decodeErr := json.Unmarshal(body, &document)
	ready := document.LifecycleState == "ACTIVE" || document.LifecycleState == "AVAILABLE" || (isOCID(id, "key") && document.LifecycleState == "ENABLED")
	if err != nil || status < 200 || status >= 300 || decodeErr != nil || document.ID != id ||
		(compartment != "" && document.CompartmentID != compartment) || (vcn != "" && document.VCNID != vcn) ||
		!ready || (requirePrivate && !document.ProhibitPublicIPOnVNIC) {
		return &InvalidDataError{Message: "OCI estate verification rejected a required resource"}
	}
	return nil
}

var _ OCIEstateReader = (*OCIEstateHTTPReader)(nil)
