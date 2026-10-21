package testorigin

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	"github.com/oracle/oci-go-sdk/v65/vault"
)

// Only the equality/pattern and bounded all/any syntax emitted by this repo is
// understood. Unknown syntax/attributes deny; an authenticated token is no grant.
func ociConditions(expression string, attributes map[string]string, depth int) (bool, bool) {
	if depth > 8 || len(expression) > 8192 {
		return false, false
	}
	expression = strings.TrimSpace(expression)
	for _, kind := range []string{"all", "any", "ALL", "ANY"} {
		if rest, ok := strings.CutPrefix(expression, kind+" {"); ok && strings.HasSuffix(rest, "}") {
			rest = rest[:len(rest)-1]
			result := strings.EqualFold(kind, "all")
			start, level, quote, count := 0, 0, byte(0), 0
			for i := 0; i <= len(rest); i++ {
				if i < len(rest) {
					c := rest[i]
					if quote != 0 {
						if c == quote {
							quote = 0
						}
						continue
					}
					if c == '\'' {
						quote = c
						continue
					}
					if c == '{' {
						level++
					}
					if c == '}' {
						level--
					}
					if level < 0 {
						return false, false
					}
					if c != ',' || level != 0 {
						continue
					}
				}
				if level != 0 || quote != 0 || count >= 128 {
					return false, false
				}
				value, valid := ociConditions(rest[start:i], attributes, depth+1)
				if !valid {
					return false, false
				}
				if strings.EqualFold(kind, "all") {
					result = result && value
				} else {
					result = result || value
				}
				count++
				start = i + 1
			}
			return result, count > 0
		}
	}
	key, literal, ok := strings.Cut(expression, "=")
	if !ok {
		return false, false
	}
	key = strings.TrimSpace(key)
	negative := strings.HasSuffix(key, "!")
	key = strings.TrimSpace(strings.TrimSuffix(key, "!"))
	if !slices.Contains([]string{"instance.id", "instance.compartment.id", "request.principal.type", "request.principal.id", "request.operation", "request.permission", "target.vault.id", "target.key.id", "target.secret.id", "target.secret.name", "target.bucket.name", "target.object.name", "target.image.id"}, key) {
		return false, false
	}
	actual, exists := attributes[key]
	literal = strings.TrimSpace(literal)
	if len(literal) < 2 {
		return false, false
	}
	var match bool
	switch {
	case literal[0] == '\'' && literal[len(literal)-1] == '\'':
		if strings.ContainsRune(literal[1:len(literal)-1], '\'') {
			return false, false
		}
		match = strings.EqualFold(actual, literal[1:len(literal)-1])
	case literal[0] == '/' && literal[len(literal)-1] == '/':
		pattern := regexp.QuoteMeta(literal[1 : len(literal)-1])
		pattern = "(?i)^" + strings.ReplaceAll(pattern, `\*`, ".*") + "$"
		match, _ = regexp.MatchString(pattern, actual)
	default:
		return false, false
	}
	if !exists || actual == "" {
		return false, true
	}
	if negative {
		match = !match
	}
	return match, true
}

type ociPermission struct{ operation, resource, permission, verb, compartment string }

// SDK custom unmarshaling drops unknown fields. Decode the supported wire
// shape directly so authorization and mutation use the same finite contract.
func decodeOCISecretCreate(body []byte) (vault.CreateSecretDetails, error) {
	var wire struct {
		CompartmentID *string                   `json:"compartmentId"`
		VaultID       *string                   `json:"vaultId"`
		KeyID         *string                   `json:"keyId"`
		SecretName    *string                   `json:"secretName"`
		Description   *string                   `json:"description"`
		FreeformTags  map[string]string         `json:"freeformTags"`
		DefinedTags   map[string]map[string]any `json:"definedTags"`
		SecretContent *struct {
			ContentType string                              `json:"contentType"`
			Content     *string                             `json:"content"`
			Stage       vault.SecretContentDetailsStageEnum `json:"stage"`
			Name        *string                             `json:"name"`
		} `json:"secretContent"`
	}
	if err := protocol.DecodeStrict(body, &wire, ociBodyLimit); err != nil {
		return vault.CreateSecretDetails{}, err
	}
	if wire.SecretContent == nil || wire.SecretContent.ContentType != "BASE64" {
		return vault.CreateSecretDetails{}, errors.New("unsupported secret content")
	}
	return vault.CreateSecretDetails{CompartmentId: wire.CompartmentID, VaultId: wire.VaultID, KeyId: wire.KeyID, SecretName: wire.SecretName,
		Description: wire.Description, FreeformTags: wire.FreeformTags, DefinedTags: wire.DefinedTags,
		SecretContent: vault.Base64SecretContentDetails{Content: wire.SecretContent.Content, Stage: wire.SecretContent.Stage, Name: wire.SecretContent.Name}}, nil
}

func (world *ociWorld) instancePermission(want ociPermission, attributes map[string]string) bool {
	attributes["request.principal.type"] = "instance"
	attributes["request.principal.id"] = *world.wire.Instance.Id
	attributes["request.operation"], attributes["request.permission"] = want.operation, want.permission
	verbs := map[string]int{"inspect": 1, "read": 2, "use": 3, "manage": 4}
	for _, policy := range world.policies {
		if policy.value.LifecycleState != identity.PolicyLifecycleStateActive || policy.value.CompartmentId == nil ||
			(*policy.value.CompartmentId != world.wire.TenancyID && *policy.value.CompartmentId != want.compartment) {
			continue
		}
		for _, statement := range policy.value.Statements {
			head, condition, ok := strings.Cut(statement, " where ")
			if !ok {
				continue
			}
			principal, tail, ok := strings.Cut(strings.TrimPrefix(head, "Allow "), " to ")
			if !ok || !strings.HasPrefix(head, "Allow ") {
				continue
			}
			if principal != "any-user" {
				name, ok := strings.CutPrefix(principal, "dynamic-group ")
				member := false
				for _, group := range world.groups {
					if ok && group.Name != nil && *group.Name == name && group.CompartmentId != nil && *group.CompartmentId == world.wire.TenancyID &&
						group.LifecycleState == identity.DynamicGroupLifecycleStateActive && group.MatchingRule != nil {
						match, valid := ociConditions(*group.MatchingRule, map[string]string{"instance.id": *world.wire.Instance.Id,
							"instance.compartment.id": *world.wire.Instance.CompartmentId}, 0)
						member = member || valid && match
					}
				}
				if !member {
					continue
				}
			}
			capability, location, ok := strings.Cut(tail, " in ")
			verb, resource, spaced := strings.Cut(capability, " ")
			if !ok || !spaced || verbs[verb] < verbs[want.verb] || (resource != want.resource && resource != "all-resources") {
				continue
			}
			if location != "compartment id "+want.compartment && location != "tenancy" {
				continue
			}
			// A tenancy grant is effective only from a root policy.
			if location == "tenancy" && *policy.value.CompartmentId != world.wire.TenancyID {
				continue
			}
			match, valid := ociConditions(condition, attributes, 0)
			if valid && match {
				return true
			}
		}
	}
	return false
}

func (world *ociWorld) authorizeInstance(request *http.Request, body []byte) bool {
	host, path := strings.TrimSuffix(request.Host, ":443"), request.URL.Path
	attributes := map[string]string{}
	compartment := *world.wire.Instance.CompartmentId
	allow := func(operation, resource, permission, verb string) bool {
		return world.instancePermission(ociPermission{operation, resource, permission, verb, compartment}, attributes)
	}
	if host == "vaults."+world.wire.Region+".oci.oraclecloud.com" {
		if path == "/20180608/secrets" && request.Method == http.MethodGet {
			compartment = request.URL.Query().Get("compartmentId")
			return allow("ListSecrets", "secrets", "SECRET_INSPECT", "inspect")
		}
		if path == "/20180608/secrets" && request.Method == http.MethodPost {
			details, err := decodeOCISecretCreate(body)
			if err != nil || details.CompartmentId == nil || details.VaultId == nil || details.KeyId == nil || details.SecretName == nil {
				return false
			}
			compartment = *details.CompartmentId
			attributes["target.vault.id"], attributes["target.key.id"], attributes["target.secret.name"] = *details.VaultId, *details.KeyId, *details.SecretName
			return allow("CreateSecret", "secrets", "SECRET_CREATE", "manage") && allow("CreateSecret", "vaults", "VAULT_CREATE_SECRET", "use") &&
				allow("CreateSecret", "keys", "KEY_ENCRYPT", "use") && allow("CreateSecret", "keys", "KEY_DECRYPT", "use")
		}
		if id, ok := strings.CutPrefix(path, "/20180608/secrets/"); ok && request.Method == http.MethodGet {
			secret, exists := world.secrets[id]
			if !exists {
				return false
			}
			compartment = *secret.value.CompartmentId
			attributes["target.secret.id"], attributes["target.secret.name"], attributes["target.vault.id"] = id, *secret.value.SecretName, *secret.value.VaultId
			return allow("GetSecret", "secrets", "SECRET_READ", "read")
		}
	}
	if host == "secrets.vaults."+world.wire.Region+".oci.oraclecloud.com" {
		for id, secret := range world.secrets {
			byName := path == "/20190301/secretbundles/actions/getByName" && request.Method == http.MethodPost && request.URL.Query().Get("secretName") == *secret.value.SecretName && request.URL.Query().Get("vaultId") == *secret.value.VaultId
			if byName || path == "/20190301/secretbundles/"+id && request.Method == http.MethodGet {
				compartment = *secret.value.CompartmentId
				attributes["target.secret.id"], attributes["target.secret.name"], attributes["target.vault.id"] = id, *secret.value.SecretName, *secret.value.VaultId
				operation := "GetSecretBundle"
				if byName {
					operation = "GetSecretBundleByName"
				}
				return allow(operation, "secret-bundles", "SECRET_BUNDLE_READ", "read")
			}
		}
		// A by-name absence still needs a scoped grant before returning 404.
		if path == "/20190301/secretbundles/actions/getByName" && request.Method == http.MethodPost {
			attributes["target.secret.name"], attributes["target.vault.id"] = request.URL.Query().Get("secretName"), request.URL.Query().Get("vaultId")
			return allow("GetSecretBundleByName", "secret-bundles", "SECRET_BUNDLE_READ", "read")
		}
	}
	if host == "identity."+world.wire.Region+".oci.oraclecloud.com" && path == "/20160918/policies" && request.Method == http.MethodPost {
		var details identity.CreatePolicyDetails
		if protocol.DecodeStrict(body, &details, ociBodyLimit) != nil || details.CompartmentId == nil {
			return false
		}
		compartment = *details.CompartmentId
		return allow("CreatePolicy", "policies", "POLICY_CREATE", "manage")
	}
	if request.Method != http.MethodGet {
		return false
	}
	if host == "iaas."+world.wire.Region+".oraclecloud.com" {
		switch path {
		case "/20160918/instances/" + *world.wire.Instance.Id:
			return allow("GetInstance", "instances", "INSTANCE_READ", "read")
		case "/20160918/images/" + *world.wire.Image.Id:
			if world.wire.Image.CompartmentId == nil {
				return false
			}
			compartment = *world.wire.Image.CompartmentId
			attributes["target.image.id"] = *world.wire.Image.Id
			return allow("GetImage", "instance-images", "INSTANCE_IMAGE_INSPECT", "read")
		case "/20160918/vnics/" + *world.wire.VNIC.Id:
			if world.wire.VNIC.CompartmentId == nil {
				return false
			}
			compartment = *world.wire.VNIC.CompartmentId
			return allow("GetVnic", "vnics", "VNIC_READ", "read")
		case "/20160918/bootVolumes/" + *world.wire.BootVolume.Id:
			return allow("GetBootVolume", "volumes", "VOLUME_INSPECT", "read")
		case "/20160918/vnicAttachments":
			return allow("ListVnicAttachments", "instances", "INSTANCE_INSPECT", "inspect") && allow("ListVnicAttachments", "vnic-attachments", "VNIC_ATTACHMENT_READ", "read")
		case "/20160918/bootVolumeAttachments":
			return allow("ListBootVolumeAttachments", "volumes", "VOLUME_INSPECT", "inspect")
		}
	}
	if host == "identity."+world.wire.Region+".oci.oraclecloud.com" {
		compartment = world.wire.TenancyID
		if strings.HasPrefix(path, "/20160918/policies/") {
			return allow("GetPolicy", "policies", "POLICY_READ", "read")
		}
		if strings.HasPrefix(path, "/20160918/dynamicGroups/") {
			return allow("GetDynamicGroup", "dynamic-groups", "DYNAMIC_GROUP_INSPECT", "read")
		}
	}
	if host == "objectstorage."+world.wire.Region+".oraclecloud.com" {
		if path == "/n" {
			compartment = world.wire.TenancyID
			return allow("GetNamespace", "objectstorage-namespaces", "OBJECTSTORAGE_NAMESPACE_READ", "read")
		}
		parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 6)
		if len(parts) >= 4 && parts[0] == "n" && parts[1] == world.wire.Namespace && parts[2] == "b" {
			for _, bucket := range world.wire.Buckets {
				if bucket.Name != nil && *bucket.Name == parts[3] && bucket.CompartmentId != nil {
					compartment = *bucket.CompartmentId
					attributes["target.bucket.name"] = parts[3]
				}
			}
			if attributes["target.bucket.name"] == "" {
				return false
			}
			if len(parts) == 4 {
				return allow("GetBucket", "buckets", "BUCKET_READ", "read")
			}
			if len(parts) == 6 && parts[4] == "o" {
				attributes["target.object.name"] = parts[5]
				return allow("GetObject", "objects", "OBJECT_READ", "read")
			}
		}
	}
	return false
}

func (world *ociWorld) serveDynamicGroups(w http.ResponseWriter, request *http.Request, body []byte) {
	const prefix = "/20160918/dynamicGroups"
	if request.URL.Path == prefix && request.Method == http.MethodPost && request.URL.RawQuery == "" {
		var details identity.CreateDynamicGroupDetails
		if protocol.DecodeStrict(body, &details, ociBodyLimit) != nil || details.CompartmentId == nil || *details.CompartmentId != world.wire.TenancyID || details.Name == nil || *details.Name == "" || len(*details.Name) > 128 || details.Description == nil || len(*details.Description) > 400 || details.MatchingRule == nil || len(world.groups) >= 128 {
			world.reject(w, 400)
			return
		}
		if _, valid := ociConditions(*details.MatchingRule, map[string]string{"instance.id": *world.wire.Instance.Id, "instance.compartment.id": *world.wire.Instance.CompartmentId}, 0); !valid {
			world.reject(w, 400)
			return
		}
		token := request.Header.Get("Opc-Retry-Token")
		digest := fmt.Sprintf("%x", sha256.Sum256(body))
		retryKey := "dynamic-group:" + token
		if token == "" || len(token) > 128 || len(request.Header.Values("Opc-Retry-Token")) != 1 {
			world.reject(w, 400)
			return
		}
		if retry, exists := world.retries[retryKey]; exists {
			group, present := world.groups[retry.id]
			if retry.request != digest || !present {
				world.reject(w, 409)
				return
			}
			w.Header().Set("ETag", world.groupETags[retry.id])
			ociJSON(w, 200, group)
			return
		}
		for _, group := range world.groups {
			if *group.Name == *details.Name {
				world.reject(w, 409)
				return
			}
		}
		id := fmt.Sprintf("ocid1.dynamicgroup.oc1..%x", sha256.Sum256([]byte(strconv.FormatUint(world.evidence.JournalRecords+1, 10)+digest)))
		group := identity.DynamicGroup{Id: new(id), CompartmentId: details.CompartmentId, Name: details.Name, Description: details.Description, MatchingRule: details.MatchingRule, LifecycleState: identity.DynamicGroupLifecycleStateActive, TimeCreated: new(common.SDKTime{Time: time.Now().UTC()}), FreeformTags: details.FreeformTags, DefinedTags: details.DefinedTags}
		wire, err := json.Marshal(group, json.Deterministic(true))
		if err != nil || world.stateBytes+len(wire) > 16<<20 || len(world.retries) >= 256 {
			world.reject(w, 507)
			return
		}
		etag, err := world.record("dynamic-group-create", id, wire)
		if err != nil {
			world.reject(w, 503)
			return
		}
		world.groups[id] = group
		world.groupETags[id] = etag
		world.stateBytes += len(wire)
		world.retries[retryKey] = ociPolicyRetry{request: digest, id: id}
		w.Header().Set("ETag", etag)
		ociJSON(w, 200, group)
		return
	}
	id, ok := strings.CutPrefix(request.URL.Path, prefix+"/")
	if !ok || strings.Contains(id, "/") || request.URL.RawQuery != "" {
		world.reject(w, 404)
		return
	}
	group, exists := world.groups[id]
	if !exists {
		world.reject(w, 404)
		return
	}
	if request.Method == http.MethodGet {
		w.Header().Set("ETag", world.groupETags[id])
		ociJSON(w, 200, group)
		return
	}
	world.reject(w, 501)
}

func (world *ociWorld) serveManagedSecrets(w http.ResponseWriter, request *http.Request, body []byte) {
	const prefix = "/20180608/secrets"
	if request.URL.Path == prefix && request.Method == http.MethodGet {
		query := request.URL.Query()
		for key, values := range query {
			if !slices.Contains([]string{"compartmentId", "vaultId", "name"}, key) || len(values) != 1 {
				world.reject(w, 400)
				return
			}
		}
		if query.Get("compartmentId") == "" || query.Get("vaultId") == "" || query.Get("name") == "" {
			world.reject(w, 400)
			return
		}
		items := []vault.SecretSummary{}
		for _, secret := range world.secrets {
			v := secret.value
			if *v.CompartmentId == query.Get("compartmentId") && *v.VaultId == query.Get("vaultId") && *v.SecretName == query.Get("name") {
				items = append(items, vault.SecretSummary{Id: v.Id, CompartmentId: v.CompartmentId, VaultId: v.VaultId, KeyId: v.KeyId, SecretName: v.SecretName, LifecycleState: vault.SecretSummaryLifecycleStateActive, TimeCreated: v.TimeCreated})
			}
		}
		ociJSON(w, 200, items)
		return
	}
	if request.URL.Path == prefix && request.Method == http.MethodPost && request.URL.RawQuery == "" {
		details, err := decodeOCISecretCreate(body)
		if err != nil || details.CompartmentId == nil || *details.CompartmentId != *world.wire.Instance.CompartmentId || details.VaultId == nil || !strings.HasPrefix(*details.VaultId, "ocid1.vault.oc1."+world.wire.Region+".") || details.KeyId == nil || !strings.HasPrefix(*details.KeyId, "ocid1.key.oc1."+world.wire.Region+".") || details.SecretName == nil || *details.SecretName == "" || len(*details.SecretName) > 255 || strings.ContainsAny(*details.SecretName, "/\\\x00") {
			world.reject(w, 400)
			return
		}
		content, ok := details.SecretContent.(vault.Base64SecretContentDetails)
		if !ok || content.Content == nil || content.Stage != vault.SecretContentDetailsStageCurrent {
			world.reject(w, 400)
			return
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(*content.Content)
		defer clear(decoded)
		if err != nil || len(decoded) == 0 || int64(len(decoded)) > bootstrap.MaxSecretBytes {
			world.reject(w, 400)
			return
		}
		token := request.Header.Get("Opc-Retry-Token")
		digest := fmt.Sprintf("%x", sha256.Sum256(body))
		retryKey := "secret:" + token
		if token == "" || len(token) > 128 || len(request.Header.Values("Opc-Retry-Token")) != 1 {
			world.reject(w, 400)
			return
		}
		if retry, exists := world.retries[retryKey]; exists {
			secret, present := world.secrets[retry.id]
			if retry.request != digest || !present {
				world.reject(w, 409)
				return
			}
			w.Header().Set("ETag", secret.etag)
			ociJSON(w, 200, secret.value)
			return
		}
		for _, secret := range world.secrets {
			if *secret.value.VaultId == *details.VaultId && *secret.value.SecretName == *details.SecretName {
				world.reject(w, 409)
				return
			}
		}
		if len(world.secrets) >= 256 || len(world.retries) >= 256 || world.stateBytes+len(body) > 16<<20 {
			world.reject(w, 507)
			return
		}
		id := fmt.Sprintf("ocid1.vaultsecret.oc1.%s.%x", world.wire.Region, sha256.Sum256([]byte(strconv.FormatUint(world.evidence.JournalRecords+1, 10)+digest)))
		value := vault.Secret{Id: new(id), CompartmentId: details.CompartmentId, VaultId: details.VaultId, KeyId: details.KeyId, SecretName: details.SecretName, Description: details.Description, CurrentVersionNumber: new(int64(1)), LifecycleState: vault.SecretLifecycleStateActive, TimeCreated: new(common.SDKTime{Time: time.Now().UTC()}), FreeformTags: details.FreeformTags, DefinedTags: details.DefinedTags}
		etag, err := world.record("secret-create", id, body)
		if err != nil {
			world.reject(w, 503)
			return
		}
		world.secrets[id] = ociManagedSecret{value: value, contents: slices.Clone(decoded), etag: etag}
		world.stateBytes += len(body)
		world.retries[retryKey] = ociPolicyRetry{request: digest, id: id}
		w.Header().Set("ETag", etag)
		ociJSON(w, 200, value)
		return
	}
	id, ok := strings.CutPrefix(request.URL.Path, prefix+"/")
	if ok && request.Method == http.MethodGet && request.URL.RawQuery == "" {
		if secret, exists := world.secrets[id]; exists {
			w.Header().Set("ETag", secret.etag)
			ociJSON(w, 200, secret.value)
			return
		}
	}
	world.reject(w, 404)
}

func (world *ociWorld) serveManagedBundle(w http.ResponseWriter, request *http.Request) bool {
	query := request.URL.Query()
	byName := request.URL.Path == "/20190301/secretbundles/actions/getByName" && request.Method == http.MethodPost
	if byName {
		for key, values := range query {
			if !slices.Contains([]string{"vaultId", "secretName", "stage", "versionNumber", "secretVersionName"}, key) || len(values) != 1 {
				world.reject(w, 400)
				return true
			}
		}
		if query.Get("vaultId") == "" || query.Get("secretName") == "" {
			world.reject(w, 400)
			return true
		}
	}
	for id, secret := range world.secrets {
		if !(byName && query.Get("vaultId") == *secret.value.VaultId && query.Get("secretName") == *secret.value.SecretName) && !(request.Method == http.MethodGet && request.URL.Path == "/20190301/secretbundles/"+id) {
			continue
		}
		if !byName {
			for key, values := range query {
				if !slices.Contains([]string{"stage", "versionNumber", "secretVersionName"}, key) || len(values) != 1 {
					world.reject(w, 400)
					return true
				}
			}
		}
		if query.Get("stage") != "" && query.Get("stage") != "CURRENT" && query.Get("stage") != "LATEST" || query.Get("versionNumber") != "" && query.Get("versionNumber") != "1" || query.Get("secretVersionName") != "" {
			world.reject(w, 404)
			return true
		}
		world.evidence.VaultReads++
		ociJSON(w, 200, secrets.SecretBundle{SecretId: new(id), VersionNumber: new(int64(1)), Stages: []secrets.SecretBundleStagesEnum{secrets.SecretBundleStagesCurrent, secrets.SecretBundleStagesLatest}, SecretBundleContent: secrets.Base64SecretBundleContentDetails{Content: new(base64.StdEncoding.EncodeToString(secret.contents))}})
		return true
	}
	if byName {
		world.reject(w, 404)
		return true
	}
	return false
}

type ociProtocolDispatch func(*http.Request) (*http.Response, error)

func (dispatch ociProtocolDispatch) Do(request *http.Request) (*http.Response, error) {
	return dispatch(request)
}

// This root crosses actual SDK IMDS acquisition, X509 federation, RSA request
// signing, current IAM, create-once Vault and bundle decoding over local TLS.
// It is protocol-simulator coverage; no installed-runtime qualification follows.
func TestOCIInstanceVaultProtocolIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const region = "sa-saopaulo-1"
	const tenancy = "ocid1.tenancy.oc1..protocol"
	const compartment = "ocid1.compartment.oc1..control"
	const instance = "ocid1.instance.oc1.sa-saopaulo-1.founder"
	const vaultID = "ocid1.vault.oc1.sa-saopaulo-1.protocol"
	const keyID = "ocid1.key.oc1.sa-saopaulo-1.protocol"
	const name = "gru-protocol-ts-orchestrator-swarm-join"
	world := &ociWorld{ctx: ctx, wire: ociWire{Region: region, TenancyID: tenancy, Instance: core.Instance{Id: new(instance), CompartmentId: new(compartment)},
		Image: core.Image{Id: new("image")}, VNIC: core.Vnic{Id: new("vnic")}, BootVolume: core.BootVolume{Id: new("boot")}},
		sessions: map[string]ociSession{}, policies: map[string]ociPolicy{}, groups: map[string]identity.DynamicGroup{}, groupETags: map[string]string{}, secrets: map[string]ociManagedSecret{}, retries: map[string]ociPolicyRetry{}, journalSHA: sha256.New(), issuer: key}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{OrganizationalUnit: []string{"opc-tenant:" + tenancy}},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), DNSNames: world.hosts(), IPAddresses: []net.IP{net.ParseIP("169.254.169.254")},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	world.leaf, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	defer clear(keyPEM)
	world.wire.IdentityCertificate, world.wire.IdentityIntermediate, world.wire.IdentityKey = certPEM, certPEM, keyPEM
	world.leafKeyID = tenancy + "/fed-x509-sha256/" + strings.ReplaceAll(fmt.Sprintf("% x", sha256.Sum256(der)), " ", ":")
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := strings.ReplaceAll(fmt.Sprintf("% x", md5.Sum(publicDER)), " ", ":")
	world.operatorKeyID, world.operatorPublic = tenancy+"/ocid1.user.oc1..operator/"+fingerprint, &key.PublicKey
	journal, err := os.CreateTemp(t.TempDir(), "journal-")
	if err != nil {
		t.Fatal(err)
	}
	world.journal = journal
	t.Cleanup(func() { _ = world.Close() })
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Host == "169.254.169.254" {
			world.serveIMDS(w, request)
		} else {
			world.serveOCI(w, request)
		}
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(world.leaf)
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
	}}
	defer transport.CloseIdleConnections()
	loseCreateReply := false
	dispatch := ociProtocolDispatch(func(request *http.Request) (*http.Response, error) {
		if request.URL.Host != "169.254.169.254" && !slices.Contains(world.hosts(), request.URL.Host) {
			return nil, errors.New("protocol request escaped local OCI hosts")
		}
		copy := request.Clone(request.Context())
		copy.URL = request.URL.Clone()
		copy.URL.Scheme = "https"
		response, err := transport.RoundTrip(copy)
		if err == nil && loseCreateReply && request.Method == http.MethodPost && request.URL.Path == "/20180608/secrets" && response.StatusCode == http.StatusOK {
			loseCreateReply = false
			_ = response.Body.Close()
			return nil, errors.New("protocol create reply lost after durable commit")
		}
		return response, err
	})
	provider, err := auth.InstancePrincipalConfigurationForRegionWithCustomClientContext(ctx, common.Region(region), func(common.HTTPRequestDispatcher) (common.HTTPRequestDispatcher, error) { return dispatch, nil })
	if err != nil {
		t.Fatal(err)
	}
	management, err := vault.NewVaultsClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	management.HTTPClient = dispatch
	bundles, err := secrets.NewSecretsClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	bundles.HTTPClient = dispatch
	operator := common.NewRawConfigurationProvider(tenancy, "ocid1.user.oc1..operator", region, fingerprint, string(keyPEM), nil)
	iam, err := identity.NewIdentityClientWithConfigurationProvider(operator)
	if err != nil {
		t.Fatal(err)
	}
	iam.HTTPClient = dispatch
	target := vaultsecret.Target{CompartmentID: compartment, VaultID: vaultID, KeyID: keyID}
	secretCount := func() int { world.mu.Lock(); defer world.mu.Unlock(); return len(world.secrets) }
	generated := 0
	produce := func(context.Context) (string, error) { generated++; return "actual-upstream-material", nil }
	if _, err := vaultsecret.Ensure(ctx, &management, target, name, "protocol", produce); err == nil || generated != 0 {
		t.Fatal("ungranted session bypassed list authorization")
	}
	group, err := iam.CreateDynamicGroup(ctx, identity.CreateDynamicGroupRequest{CreateDynamicGroupDetails: identity.CreateDynamicGroupDetails{CompartmentId: new(tenancy), Name: new("controller"), Description: new("protocol"), MatchingRule: new("ALL {instance.compartment.id='" + compartment + "'}")}, OpcRetryToken: new("group-create")})
	if err != nil || group.Id == nil {
		t.Fatal("SDK dynamic-group create failed", err)
	}
	groupRead, err := iam.GetDynamicGroup(ctx, identity.GetDynamicGroupRequest{DynamicGroupId: group.Id})
	if err != nil || groupRead.Id == nil || *groupRead.Id != *group.Id || groupRead.MatchingRule == nil || *groupRead.MatchingRule != "ALL {instance.compartment.id='"+compartment+"'}" || group.Etag == nil || *group.Etag == "" || groupRead.Etag == nil || *groupRead.Etag != *group.Etag {
		t.Fatal("SDK dynamic-group readback failed", err)
	}
	grant := func(statements []string, token string) identity.CreatePolicyResponse {
		t.Helper()
		response, err := iam.CreatePolicy(ctx, identity.CreatePolicyRequest{CreatePolicyDetails: identity.CreatePolicyDetails{CompartmentId: new(tenancy), Name: new(token), Description: new("protocol"), Statements: statements}, OpcRetryToken: new(token)})
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	read := "Allow dynamic-group controller to inspect secrets in compartment id " + compartment + " where all {request.operation='ListSecrets', request.permission='SECRET_INSPECT'}"
	grant([]string{read}, "read-only")
	if _, err := vaultsecret.Ensure(ctx, &management, target, name, "protocol", produce); err == nil || secretCount() != 0 {
		t.Fatal("current read-only controller policy created join material")
	}
	if generated != 1 {
		t.Fatal("create path was not reached after authorized absence")
	}
	principal := "request.principal.type='instance', request.principal.id='" + instance + "'"
	creation := []string{}
	for _, row := range [][3]string{{"manage", "secrets", "SECRET_CREATE"}, {"use", "vaults", "VAULT_CREATE_SECRET"}, {"use", "keys", "KEY_ENCRYPT"}, {"use", "keys", "KEY_DECRYPT"}} {
		creation = append(creation, fmt.Sprintf("Allow any-user to %s %s in compartment id %s where all {%s, request.operation='CreateSecret', request.permission='%s', target.secret.name='%s', target.vault.id='%s', target.key.id='%s'}", row[0], row[1], compartment, principal, row[2], name, vaultID, keyID))
	}
	invalid := slices.Clone(creation)
	invalid[0] = "Allow any-user to manage secrets in compartment id " + compartment + " where any {request.permission='SECRET_CREATE', unknown.attr=malformed}"
	invalidPolicy := grant(invalid, "invalid-syntax")
	if _, err := vaultsecret.Ensure(ctx, &management, target, name, "protocol", produce); err == nil || secretCount() != 0 {
		t.Fatal("malformed condition under any granted creation")
	}
	if _, err := iam.DeletePolicy(ctx, identity.DeletePolicyRequest{PolicyId: invalidPolicy.Id, IfMatch: invalidPolicy.Etag}); err != nil {
		t.Fatal(err)
	}
	// The refused value generation above is expected; no content was committed.
	if generated != 2 {
		t.Fatal("invalid-syntax denial did not reach the real create boundary")
	}
	grant(creation, "founder-create")
	for _, mutation := range []string{"root", "content"} {
		content := map[string]any{"contentType": "BASE64", "content": base64.StdEncoding.EncodeToString([]byte("refused")), "stage": "CURRENT"}
		wire := map[string]any{"compartmentId": compartment, "vaultId": vaultID, "keyId": keyID, "secretName": name, "secretContent": content}
		if mutation == "root" {
			wire["unknown"] = true
		} else {
			content["unknown"] = true
		}
		body, err := json.Marshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		for _, caller := range []struct {
			name   string
			key    common.KeyProvider
			status int
		}{{"instance", provider, http.StatusForbidden}, {"operator", operator, http.StatusBadRequest}} {
			request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://vaults."+region+".oci.oraclecloud.com/20180608/secrets", bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
			request.Header.Set("Opc-Retry-Token", "unknown-"+mutation+"-"+caller.name)
			if err := common.DefaultRequestSigner(caller.key).Sign(request); err != nil {
				t.Fatal(err)
			}
			response, err := dispatch.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != caller.status || secretCount() != 0 {
				t.Fatalf("%s accepted unknown %s secret field: status %d", caller.name, mutation, response.StatusCode)
			}
		}
	}
	for _, mutation := range []string{"name", "vault", "key", "compartment"} {
		details := vault.CreateSecretDetails{CompartmentId: new(compartment), VaultId: new(vaultID), KeyId: new(keyID), SecretName: new(name), SecretContent: vault.Base64SecretContentDetails{Content: new(base64.StdEncoding.EncodeToString([]byte("refused"))), Stage: vault.SecretContentDetailsStageCurrent}}
		switch mutation {
		case "name":
			details.SecretName = new(name + "-foreign")
		case "vault":
			details.VaultId = new(vaultID + "foreign")
		case "key":
			details.KeyId = new(keyID + "foreign")
		case "compartment":
			details.CompartmentId = new(compartment + "foreign")
		}
		if _, err := management.CreateSecret(ctx, vault.CreateSecretRequest{CreateSecretDetails: details, OpcRetryToken: new("refuse-" + mutation)}); err == nil || secretCount() != 0 {
			t.Fatal("founder policy authorized foreign " + mutation)
		}
	}
	loseCreateReply = true
	stored, err := vaultsecret.Ensure(ctx, &management, target, name, "protocol", produce)
	if err != nil || stored.ID == "" || generated != 3 || loseCreateReply {
		t.Fatal("founder create/lost-response recovery failed", err)
	}
	readGrant := func(operation string) string {
		return "Allow dynamic-group controller to read secret-bundles in compartment id " + compartment + " where all {request.operation='" + operation + "', request.permission='SECRET_BUNDLE_READ', target.vault.id='" + vaultID + "', target.secret.name='" + name + "'}"
	}
	grant([]string{readGrant("GetSecretBundle")}, "id-read-only")
	if _, err := vaultsecret.Read(ctx, &bundles, vaultID, name); err == nil {
		t.Fatal("ID-only operation grant authorized a by-name read")
	}
	policy := grant([]string{readGrant("GetSecretBundleByName")}, "by-name-read")
	value, err := vaultsecret.ReadBack(ctx, &bundles, vaultID, name, true)
	if err != nil || value != "actual-upstream-material" {
		t.Fatal("real SDK bundle readback failed", err)
	}
	again, err := vaultsecret.Ensure(ctx, &management, target, name, "protocol", produce)
	if err != nil || again.Created || again.ID != stored.ID || generated != 3 {
		t.Fatal("create-once recovery regenerated material", err)
	}
	if _, err := vaultsecret.Ensure(ctx, &management, target, name+"-foreign", "protocol", produce); err == nil || secretCount() != 1 {
		t.Fatal("exact founder policy authorized a foreign name")
	}
	_, err = iam.DeletePolicy(ctx, identity.DeletePolicyRequest{PolicyId: policy.Id, IfMatch: policy.Etag})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vaultsecret.Read(ctx, &bundles, vaultID, name); err == nil {
		t.Fatal("deleted policy remained authorized")
	}
	world.mu.Lock()
	for token, session := range world.sessions {
		session.expires = time.Now().Add(-time.Second)
		world.sessions[token] = session
	}
	world.mu.Unlock()
	if _, err := vaultsecret.Ensure(ctx, &management, target, name, "protocol", produce); err == nil {
		t.Fatal("expired federation session remained authorized")
	}
	evidence, err := world.Evidence()
	if err != nil || evidence.Federations == 0 || evidence.JournalRecords < 4 {
		t.Fatal("SDK federation or durable mutation evidence absent", err)
	}
}
