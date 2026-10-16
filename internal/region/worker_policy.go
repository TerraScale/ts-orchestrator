package region

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

// WorkerPolicyRecord is provider-effect history, not worker admission. Only
// the root runtime's actual current cluster may authorize its worker material.
type WorkerPolicyRecord struct {
	OperationID    string                       `json:"operationId"`
	InstanceID     string                       `json:"instanceId"`
	SecretID       string                       `json:"secretId"`
	SecretVersion  int64                        `json:"secretVersion"`
	MaterialSHA256 string                       `json:"materialSha256"`
	PolicyID       string                       `json:"policyId,omitempty"`
	Request        identity.CreatePolicyDetails `json:"request"`
	RequestDigest  string                       `json:"requestDigest"`
	RetryToken     string                       `json:"retryToken"`
	FirstAttemptAt time.Time                    `json:"firstAttemptAt"`
}

// WorkerPolicyKey identifies exactly one immutable instance/secret grant.
func WorkerPolicyKey(instance, secret string) string {
	sum := sha256.Sum256([]byte(instance + "\x00" + secret))
	return hex.EncodeToString(sum[:])
}

var workerSecretPattern = regexp.MustCompile(`^ocid1\.vaultsecret\.oc1\.[a-z0-9-]+\.[a-z0-9]+(?:\.[a-z0-9]+)*$`)

func (record WorkerPolicyRecord) validate(key string) error {
	if !entityid.Valid(record.OperationID) || key != WorkerPolicyKey(record.InstanceID, record.SecretID) || !sourceInstancePattern.MatchString(record.InstanceID) || !sourceDigest(record.MaterialSHA256) ||
		len(record.InstanceID) > 512 || len(record.SecretID) > 512 || !sourceDigest(record.RequestDigest) || !sourceDigest(record.RetryToken) || record.SecretVersion < 1 || record.FirstAttemptAt.IsZero() ||
		record.Request.CompartmentId == nil || !sourceCompartmentPattern.MatchString(*record.Request.CompartmentId) || record.PolicyID != "" && !validAuxiliaryID("controller_usage_policy", record.PolicyID, "") {
		return errors.New("worker IAM journal has invalid exact recipient or effect identity")
	}
	// SDK secret IDs are region-qualified; an arbitrary resource family never qualifies.
	if !workerSecretPattern.MatchString(record.SecretID) {
		return errors.New("worker IAM journal is not an exact Vault secret")
	}
	expected := identity.CreatePolicyDetails{CompartmentId: new(*record.Request.CompartmentId), Name: new("ts-worker-read-" + key[:32]), Description: new("Exact enrolled worker reads one worker-only Vault secret"), Statements: []string{fmt.Sprintf("Allow any-user to read secret-bundles in compartment id %s where all {request.principal.type='instance', request.principal.id='%s', target.secret.id='%s', request.permission='SECRET_BUNDLE_READ'}", *record.Request.CompartmentId, record.InstanceID, record.SecretID)}}
	expectedWire, err := json.Marshal(expected, json.Deterministic(true))
	if err != nil {
		return err
	}
	requestWire, err := json.Marshal(record.Request, json.Deterministic(true))
	if err != nil {
		return err
	}
	if string(expectedWire) != string(requestWire) || digestSource(requestWire) != record.RequestDigest || record.RetryToken != digestSource([]byte(record.OperationID+"\x00"+key+"\x00"+record.RequestDigest)) {
		return errors.New("worker IAM journal changed its exact immutable request")
	}
	return nil
}
