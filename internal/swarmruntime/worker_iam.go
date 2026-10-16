package swarmruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/moby/swarmkit/v2/api"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"

	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// The root manager derives the expected bytes from its actual upstream cluster.
// An enrollment signature or a caller-selected secret reference is insufficient.
func (n *Node) currentWorkerVaultGrant(ctx context.Context, accepted hostenroll.VerifiedSwarmWorker, query WorkerRegistrationQuery, phase workerRegistrationPhase) error {
	authority := n.workerAuthority
	if authority == nil || authority.homeIAM == nil || authority.foundations.Store == nil {
		return errors.New("worker Vault IAM requires current root and shared home authority")
	}
	if err := authority.homeIAM.Guard(ctx, 0); err != nil {
		return err
	}
	request, response, registration, observed, execution, err := authority.currentInPhase(ctx, query, phase)
	if err != nil {
		return err
	}
	role, architecture, _ := strings.Cut(execution, ":")
	var transport hostenroll.WorkerTransport
	if json.Unmarshal(accepted.Wire(), &transport, json.RejectUnknownMembers(true)) != nil || !bytes.Equal(transport.Request, query.Request) || !bytes.Equal(transport.Response, query.Response) {
		return errors.New("worker IAM transport differs from current enrollment")
	}
	_, descriptor, err := hostenroll.ParseRetainedWorkerRequest(query.Request, time.Now().UTC())
	if err != nil {
		return err
	}
	verified, err := hostenroll.VerifyWorkerTransport(accepted.Wire(), authority.public, hostenroll.InstanceMetadata{InstanceID: request.InstanceID, Descriptor: descriptor}, architecture, time.Now().UTC())
	if err != nil || verified.Worker() != accepted.Worker() {
		return errors.New("worker IAM projection lacks the current root enrollment authority")
	}
	worker := accepted.Worker()
	if worker.Generation != registration.Generation || worker.Revision != response.RegistrationReceipt.Revision || worker.PrivateIP != observed.PrimaryPrivateIP || worker.Role != role {
		return errors.New("worker IAM recipient differs from current registered execution role")
	}
	control, err := n.ControlClient(ctx)
	if err != nil {
		return err
	}
	clusters, err := control.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil || len(clusters.Clusters) != 1 {
		return errors.New("worker IAM needs one observed upstream cluster")
	}
	cluster := clusters.Clusters[0]
	material := workerJoinMaterial{Version: 1, DeploymentID: authority.identity.DeploymentID, ClusterID: authority.identity.ClusterID, Environment: authority.identity.Environment, Region: authority.identity.OCIRegion, FounderID: authority.identity.SeedSlot, RegistrationID: registration.ID, InstanceID: request.InstanceID, Role: role, Architecture: architecture, SwarmID: cluster.ID, CAPEM: string(cluster.RootCA.CACert), ManagerAddress: net.JoinHostPort(authority.identity.SeedPrivateIP, swarmManagerPort), WorkerToken: cluster.RootCA.JoinTokens.Worker}
	if !workerMaterialMatches(material, worker) || material.WorkerToken == "" || material.WorkerToken == cluster.RootCA.JoinTokens.Manager {
		return errors.New("worker IAM material differs from the actual worker-only upstream token")
	}
	expected, err := json.Marshal(material)
	if err != nil {
		return err
	}
	defer clear(expected)
	if workerIAMDigest(expected) != worker.SecretSHA256 {
		return errors.New("worker IAM signed digest differs from root-derived worker material")
	}
	foundation, err := authority.foundations.Resolve(ctx, strings.ToUpper(authority.identity.Cell))
	if err != nil {
		return err
	}
	target, err := foundation.VaultTarget()
	if err != nil || target != authority.target || foundation.OCIRegion != worker.OCIRegion {
		return errors.New("worker IAM Vault differs from the current trusted regional foundation")
	}
	name := vaultsecret.Name(strings.ToLower(authority.identity.Cell)+"-"+strings.ToLower(authority.identity.ClusterID)+"-"+strings.ToLower(registration.ID)+"-"+worker.SecretSHA256, "TS_ORCHESTRATOR_SWARM_WORKER")
	factory, _, err := authority.homeIAM.GuardedFactory(ctx)
	if err != nil {
		return err
	}
	factory, err = factory.ForRegion(worker.OCIRegion)
	if err != nil {
		return err
	}
	metadata, err := ocivault.NewVaultsClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		return err
	}
	metadata.SetRegion(worker.OCIRegion)
	factory.Configure(&metadata.BaseClient, ociclient.ServiceVault)
	actual, err := metadata.GetSecret(ociclient.RequestContext(ctx), ocivault.GetSecretRequest{SecretId: new(worker.SecretID)})
	if err != nil {
		return err
	}
	if actual.Id == nil || *actual.Id != worker.SecretID || actual.SecretName == nil || *actual.SecretName != name || actual.CompartmentId == nil || *actual.CompartmentId != target.CompartmentID || actual.VaultId == nil || *actual.VaultId != target.VaultID || actual.KeyId == nil || *actual.KeyId != target.KeyID || actual.LifecycleState != ocivault.SecretLifecycleStateActive || actual.CurrentVersionNumber == nil || *actual.CurrentVersionNumber != worker.SecretVersion {
		return errors.New("actual worker Vault secret differs from its exact owned recipient target")
	}
	bundles, err := vaultsecret.SecretsClient(factory)
	if err != nil {
		return err
	}
	bundle, err := bundles.GetSecretBundle(ociclient.RequestContext(ctx), secrets.GetSecretBundleRequest{SecretId: new(worker.SecretID), VersionNumber: new(worker.SecretVersion)})
	if err != nil {
		return err
	}
	if bundle.SecretId == nil || *bundle.SecretId != worker.SecretID || bundle.VersionNumber == nil || *bundle.VersionNumber != worker.SecretVersion {
		return errors.New("worker IAM bundle differs from its exact signed version")
	}
	var encoded *string
	switch content := bundle.SecretBundleContent.(type) {
	case secrets.Base64SecretBundleContentDetails:
		encoded = content.Content
	case *secrets.Base64SecretBundleContentDetails:
		if content != nil {
			encoded = content.Content
		}
	}
	if encoded == nil || len(*encoded) > 24<<10 {
		return errors.New("worker IAM bundle content is missing or oversized")
	}
	value, err := base64.StdEncoding.Strict().DecodeString(*encoded)
	if err != nil {
		return errors.New("worker IAM bundle encoding is invalid")
	}
	defer clear(value)
	if !bytes.Equal(value, expected) {
		return errors.New("actual Vault bytes differ from root-derived worker-only material")
	}
	return nil
}

func (n *Node) authorizeWorkerVaultRead(ctx context.Context, accepted hostenroll.VerifiedSwarmWorker, query WorkerRegistrationQuery, phase workerRegistrationPhase) error {
	if err := n.currentWorkerVaultGrant(ctx, accepted, query, phase); err != nil {
		return err
	}
	authority := n.workerAuthority
	ctx, release, err := authority.homeIAM.HomeWrite(ctx, 0)
	if err != nil {
		return err
	}
	defer release()
	guard := func(ctx context.Context) error { return n.currentWorkerVaultGrant(ctx, accepted, query, phase) }
	ctx = ociclient.WithAuthority(ctx, guard)
	if err := guard(ctx); err != nil {
		return err
	}
	worker := accepted.Worker()
	record, etag, err := authority.foundations.Store.Load(ctx, strings.ToUpper(authority.identity.Cell))
	if err != nil {
		return err
	}
	current, err := authority.foundations.Resolve(ctx, record.Cell)
	if err != nil || current.Generation != record.Generation || current.OperationID != record.OperationID || current.Stage != record.Stage {
		return errors.Join(region.ErrFoundationFenced, err)
	}
	factory, _, err := authority.homeIAM.GuardedFactory(ctx)
	if err != nil {
		return err
	}
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil {
		return err
	}
	home, err := factory.HomeRegion(ctx, tenancy)
	if err != nil {
		return err
	}
	factory, err = factory.ForRegion(home)
	if err != nil {
		return err
	}
	iam, err := factory.Identity()
	if err != nil {
		return err
	}
	key := region.WorkerPolicyKey(worker.InstanceID, worker.SecretID)
	details := identity.CreatePolicyDetails{CompartmentId: new(authority.target.CompartmentID), Name: new("ts-worker-read-" + key[:32]), Description: new("Exact enrolled worker reads one worker-only Vault secret"), Statements: []string{fmt.Sprintf("Allow any-user to read secret-bundles in compartment id %s where all {request.principal.type='instance', request.principal.id='%s', target.secret.id='%s', request.permission='SECRET_BUNDLE_READ'}", authority.target.CompartmentID, worker.InstanceID, worker.SecretID)}}
	wire, err := json.Marshal(details, json.Deterministic(true))
	if err != nil {
		return err
	}
	pending, exists := record.WorkerPolicyIDs[key]
	observedID, err := findWorkerIAMPolicy(ctx, &iam, details)
	if err != nil {
		return err
	}
	if !exists && observedID != "" {
		return errors.New("worker IAM policy has no authenticated pending-create origin")
	}
	if exists {
		if pending.InstanceID != worker.InstanceID || pending.SecretID != worker.SecretID || pending.SecretVersion != worker.SecretVersion || pending.MaterialSHA256 != worker.SecretSHA256 || pending.RequestDigest != workerIAMDigest(wire) {
			return errors.New("worker IAM journal belongs to another exact recipient material")
		}
	} else {
		if len(record.WorkerPolicyIDs) >= 256 {
			return errors.New("worker IAM journal is full")
		}
		pending = region.WorkerPolicyRecord{OperationID: record.OperationID, InstanceID: worker.InstanceID, SecretID: worker.SecretID, SecretVersion: worker.SecretVersion, MaterialSHA256: worker.SecretSHA256, Request: details, RequestDigest: workerIAMDigest(wire), FirstAttemptAt: time.Now().UTC()}
		pending.RetryToken = workerIAMDigest([]byte(record.OperationID + "\x00" + key + "\x00" + pending.RequestDigest))
		record.WorkerPolicyIDs = maps.Clone(record.WorkerPolicyIDs)
		if record.WorkerPolicyIDs == nil {
			record.WorkerPolicyIDs = map[string]region.WorkerPolicyRecord{}
		}
		record.WorkerPolicyIDs[key] = pending
		if err := guard(ctx); err != nil {
			return err
		}
		etag, err = authority.foundations.Store.CompareAndSwap(ctx, record, etag)
		if err != nil {
			return err
		}
	}
	verify := func(id string) error {
		response, err := iam.GetPolicy(ociclient.RequestContext(ctx), identity.GetPolicyRequest{PolicyId: new(id)})
		if err != nil {
			return err
		}
		if response.Id == nil || *response.Id != id || response.Name == nil || *response.Name != *details.Name || response.CompartmentId == nil || *response.CompartmentId != *details.CompartmentId || response.LifecycleState != identity.PolicyLifecycleStateActive || !slices.Equal(response.Statements, details.Statements) {
			return errors.New("actual worker IAM policy differs from its exact read-only recipient request")
		}
		return nil
	}
	if pending.PolicyID != "" {
		if observedID != "" && observedID != pending.PolicyID {
			return errors.New("worker IAM policy resolves to another provider identity")
		}
		if err := verify(pending.PolicyID); err != nil {
			return err
		}
		return guard(ctx)
	}
	if time.Since(pending.FirstAttemptAt) >= 23*time.Hour || pending.FirstAttemptAt.After(time.Now().UTC()) {
		return errors.New("worker IAM pending create is outside the exact-token retry window")
	}
	if err := guard(ctx); err != nil {
		return err
	}
	noRetry := common.NoRetryPolicy()
	created, err := iam.CreatePolicy(ociclient.RequestContext(ctx), identity.CreatePolicyRequest{CreatePolicyDetails: pending.Request, OpcRetryToken: new(pending.RetryToken), RequestMetadata: common.RequestMetadata{RetryPolicy: &noRetry}})
	if err != nil {
		return err
	}
	if created.Id == nil || !workerIAMPolicyID(*created.Id) || observedID != "" && *created.Id != observedID {
		return errors.New("worker IAM create replay differs from the exact observed policy identity")
	}
	if err := verify(*created.Id); err != nil {
		return err
	}
	pending.PolicyID = *created.Id
	record.WorkerPolicyIDs[key] = pending
	if err := guard(ctx); err != nil {
		return err
	}
	_, err = authority.foundations.Store.CompareAndSwap(ctx, record, etag)
	return err
}

func workerIAMDigest(wire []byte) string {
	sum := sha256.Sum256(wire)
	return hex.EncodeToString(sum[:])
}
func workerIAMPolicyID(id string) bool {
	suffix, ok := strings.CutPrefix(id, "ocid1.policy.oc1..")
	if !ok || suffix == "" || len(id) > 512 {
		return false
	}
	for _, char := range suffix {
		if char != '.' && (char < 'a' || char > 'z') && (char < '0' || char > '9') {
			return false
		}
	}
	return !strings.Contains(suffix, "..") && !strings.HasSuffix(suffix, ".")
}
func findWorkerIAMPolicy(ctx context.Context, iam *identity.IdentityClient, details identity.CreatePolicyDetails) (string, error) {
	id := ""
	var page *string
	seen := map[string]struct{}{}
	for {
		response, err := iam.ListPolicies(ociclient.RequestContext(ctx), identity.ListPoliciesRequest{CompartmentId: details.CompartmentId, Name: details.Name, Page: page})
		if err != nil {
			return "", err
		}
		for _, policy := range response.Items {
			if policy.Name == nil || *policy.Name != *details.Name {
				continue
			}
			if policy.Id == nil || !workerIAMPolicyID(*policy.Id) || id != "" {
				return "", errors.New("worker IAM policy discovery is ambiguous")
			}
			id = *policy.Id
		}
		if response.OpcNextPage == nil || *response.OpcNextPage == "" {
			return id, nil
		}
		next := *response.OpcNextPage
		if _, ok := seen[next]; ok {
			return "", errors.New("worker IAM policy discovery repeated its page")
		}
		seen[next] = struct{}{}
		page = new(next)
	}
}
