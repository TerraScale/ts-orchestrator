package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/machines"
	"github.com/TerraScale/ts-orchestrator/internal/machinesapi"
	"github.com/TerraScale/ts-orchestrator/internal/managedmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/storage/execution"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/tenant"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/api/genericresource"
	"github.com/nats-io/nats.go/jetstream"
)

// The broker, authority, SwarmKit manager/scheduler and authenticated HTTP are
// real. The local executor simulates application lifecycle, not native execution.
func TestMachinesManagerAuthenticatedHTTPIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	auth := newAuthenticatedNATS(t, "gru")
	broker, err := auth.start(t, ctx, natscell.Config{Cell: "gru", Replicas: 1, Embedded: &natscell.Embedded{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	identity := cellspec.Identity{DeploymentID: entityid.New(), Cell: "gru", Environment: "canary"}
	control, err := authority.Start(ctx, broker.JetStream(), authority.Config{DeploymentID: identity.DeploymentID, Scope: "gru", CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	resources := placement.Resources{CPU: 1, MemoryBytes: 64 << 20, DiskBytes: 1 << 30}
	keys := newTestSpecTrust(t, t.TempDir(), identity)
	specs := &specRegistry{cell: identity.Cell, identity: identity, fixed: map[string]WorkloadProfile{}}
	if err := specs.openRoots(keys.roots, trust.RootChain{Version: 1}, ""); err != nil {
		t.Fatal(err)
	}
	specs.kv, err = broker.JetStream().CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: cellSpecBucket, Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	policy := workload.ServiceSpec{Role: "api", Environment: identity.Environment, Kind: workload.KindStateless, Replicas: workload.ReplicaBounds{Min: 1, Max: 2}}
	signed := keys.signRoot(t, t.TempDir(), cellspec.Spec{Schema: cellspec.Schema, Identity: identity, Generation: 1, RequiresBinary: cellspec.BinaryLevel, Services: []cellspec.Service{{Role: "api", Profile: WorkloadProfile{Resources: resources}, Spec: &policy}}})
	wire, err := os.ReadFile(signed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := specs.kv.Put(ctx, cellSpecKey, wire); err != nil {
		t.Fatal(err)
	}
	entry, err := specs.kv.Get(ctx, cellSpecKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := specs.load(entry); err != nil {
		t.Fatal(err)
	}
	manager := startGenericRuntimeNode(t, ctx, genericRuntimeNodeConfig(t, "generic-manager", "manager"), &genericRuntimeExecutor{controllers: map[string]*genericRuntimeTask{}})
	client, err := manager.ControlClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := swarmruntime.AdmitNode(ctx, client, manager.ID(), genericRuntimeNodeConfigAdmission("generic-manager", "manager")); err != nil {
		t.Fatal(err)
	}
	var ready atomic.Bool
	var changeDuringProbe atomic.Bool
	view := &managerWorkloadView{client: client, managerID: manager.ID(), authority: control, specs: specs}
	view.probe = func(probeCtx context.Context, task *api.Task) error {
		if changeDuringProbe.Swap(false) {
			current, err := client.GetService(probeCtx, &api.GetServiceRequest{ServiceID: task.ServiceID})
			if err != nil {
				return err
			}
			next := current.Service.Spec.Copy()
			next.GetReplicated().Replicas = 2
			_, err = client.UpdateService(probeCtx, &api.UpdateServiceRequest{ServiceID: task.ServiceID, ServiceVersion: &current.Service.Meta.Version, Spec: next})
			if err != nil {
				return err
			}
		}
		if !ready.Load() {
			return errors.New("application is not ready")
		}
		return nil
	}
	genericRuntimeEventually(t, ctx, func() bool { return view.leader(ctx, control.Current().Epoch) })
	runtime, err := swarmruntime.ContainerRuntime(&api.ContainerSpec{Image: "example.invalid/api@sha256:" + strings.Repeat("a", 64), User: "65532:65532", Env: []string{"SECRET=never-return-this"}})
	if err != nil {
		t.Fatal(err)
	}
	limits := &api.Resources{NanoCPUs: 1_000_000_000, MemoryBytes: 64 << 20, Generic: []*api.GenericResource{genericresource.NewDiscrete(swarmruntime.DiskResource, 1<<30)}}
	base := &api.ServiceSpec{Annotations: api.Annotations{Name: "machines-api", Labels: map[string]string{
		swarmruntime.LabelIntentID: entityid.Derive("platform-service", "api", identity.Environment, "sa-saopaulo-1"), swarmruntime.LabelRole: "api", swarmruntime.LabelRegion: "sa-saopaulo-1", swarmruntime.LabelEnvironment: identity.Environment,
	}}, Task: api.TaskSpec{Runtime: runtime, Resources: &api.ResourceRequirements{Limits: limits, Reservations: limits.Copy()}}, Mode: &api.ServiceSpec_Replicated{Replicated: &api.ReplicatedService{Replicas: 1}}}
	created, err := client.CreateService(ctx, &api.CreateServiceRequest{Spec: base})
	if err != nil {
		t.Fatal(err)
	}
	genericRuntimeEventually(t, ctx, func() bool {
		tasks, err := client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{created.Service.ID}}})
		return err == nil && len(tasks.Tasks) == 1 && tasks.Tasks[0].Status.State == api.TaskStateRunning
	})
	tenants, err := tenant.OpenStore(ctx, broker.JetStream(), 1)
	if err != nil {
		t.Fatal(err)
	}
	platformOrg, tenantOrg, otherOrg := entityid.New(), entityid.New(), entityid.New()
	platformSub, tenantSub, otherSub, clientID := entityid.New(), entityid.New(), entityid.New(), entityid.New()
	tenantID := entityid.New()
	record, err := tenant.New(tenantID, tenantOrg, entityid.New(), "gru", tenant.Spec{Plan: "starter", Members: 1, TerraBase: strings.Repeat("a", 64)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tenants.Create(ctx, record); err != nil {
		t.Fatal(err)
	}
	// An unplaced tenant function must remain visible only to its organization.
	function := base.Copy()
	function.Annotations.Name = "machines-function"
	function.Annotations.Labels[swarmruntime.LabelRole] = swarmruntime.FunctionWorkerRole
	function.Annotations.Labels[swarmruntime.LabelFunctionTenant] = tenantID
	function.Annotations.Labels[swarmruntime.LabelFunctionID] = "echo"
	functionID := entityid.Derive("function-service", identity.Environment, "sa-saopaulo-1", tenantID, "echo")
	function.Annotations.Labels[swarmruntime.LabelIntentID] = functionID
	function.Task.Placement = &api.Placement{Constraints: []string{"node.labels.test-unavailable==true"}}
	if _, err := client.CreateService(ctx, &api.CreateServiceRequest{Spec: function}); err != nil {
		t.Fatal(err)
	}
	members, admitted, states := machinesAdmittedPlacement(t, ctx, broker, control)
	databaseTenant, err := tenant.New(admitted.CanonicalRoster.TenantID, tenantOrg, entityid.New(), "gru", tenant.Spec{Plan: "starter", Members: 1, TerraBase: strings.Repeat("a", 64)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tenants.Create(ctx, databaseTenant); err != nil {
		t.Fatal(err)
	}
	var memberServiceID string
	for index, state := range states {
		memberSpec := base.Copy()
		memberSpec.Annotations.Name = fmt.Sprintf("machines-member-%d", index)
		memberSpec.Annotations.Labels = map[string]string{
			swarmruntime.LabelIntentID: entityid.Derive("stateful-service", identity.Environment, identity.Cell, state.DatabaseID, state.PartitionID, state.MemberID),
			swarmruntime.LabelRole:     "terrabase", swarmruntime.LabelRegion: "sa-saopaulo-1", swarmruntime.LabelEnvironment: identity.Environment,
			"terrascale.stateful": "true", "terrascale.database-id": state.DatabaseID, "terrascale.partition-id": state.PartitionID, "terrascale.member-id": state.MemberID, "terrascale.placement-sha256": admitted.PayloadDigest(),
		}
		memberSpec.Task.GetGeneric().Kind = execution.StatefulContainerKind
		memberSpec.Task.GetGeneric().Payload.TypeUrl = execution.StatefulContainerTypeURL
		memberSpec.Task.Placement = &api.Placement{Constraints: []string{"node.labels.test-unavailable==true"}}
		response, err := client.CreateService(ctx, &api.CreateServiceRequest{Spec: memberSpec})
		if err != nil {
			t.Fatal(err)
		}
		memberServiceID = response.Service.ID
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := key.PublicKey.Bytes()
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		wire, _ := json.Marshal(map[string]any{"keys": []map[string]string{{"kty": "EC", "crv": "P-256", "kid": "k1", "x": base64.RawURLEncoding.EncodeToString(public[1:33]), "y": base64.RawURLEncoding.EncodeToString(public[33:])}}})
		_, _ = w.Write(wire)
	}))
	t.Cleanup(jwks.Close)
	issuer, audience := "https://gru.auth.terrascale.tech/terrascale", "https://gru.orch.terrascale.tech"
	cfg := Config{NATS: natscell.Config{Cell: "gru", Replicas: 1}, Controller: ControllerConfig{MachinesAPI: &machinesapi.Config{ListenAddress: fmt.Sprintf("127.0.0.1:%d", freeTCPPort(t)), Issuer: issuer, Audience: audience, JWKSURLs: []string{jwks.URL}, Clients: []string{clientID}, PlatformOrganizationID: platformOrg, Members: map[string][]string{platformOrg: {platformSub}, tenantOrg: {tenantSub}, otherOrg: {otherSub}}}}}
	serving, err := startMachinesAPI(ctx, cfg, broker, control, func() bool { return true }, newManagerMachinesView(view, members), nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = serving
	token := func(subject string) string {
		now := time.Now().Unix()
		return signTestAccessToken(t, key, "k1", map[string]any{"iss": issuer, "aud": audience, "sub": subject, "client_id": clientID, "scope": "orch:read", "iat": now, "exp": now + 600})
	}
	get := func(subject, path string) (int, []byte) {
		t.Helper()
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+cfg.Controller.MachinesAPI.ListenAddress+path, nil)
		if subject != "" {
			request.Header.Set("Authorization", "Bearer "+token(subject))
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		wire, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, wire
	}
	if code, wire := get("", "/v1/apps"); code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d %s", code, wire)
	}
	var first machinesapi.MachineView
	genericRuntimeEventually(t, ctx, func() bool {
		code, wire := get(platformSub, "/v1/apps/api/machines")
		var body struct {
			Machines []machinesapi.MachineView `json:"machines"`
		}
		if code != http.StatusOK || json.Unmarshal(wire, &body) != nil || len(body.Machines) != 1 {
			return false
		}
		first = body.Machines[0]
		return first.Status != nil && first.Status.State == machines.StateStarting
	})
	if !entityid.Valid(first.ID) || first.Config.Digest != strings.Repeat("a", 64) {
		t.Fatalf("actual task projection: %+v", first)
	}
	ready.Store(true)
	if code, wire := get(platformSub, "/v1/apps/api/machines/"+first.ID); code != http.StatusOK || !strings.Contains(string(wire), `"state":"started"`) || strings.Contains(string(wire), "never-return-this") {
		t.Fatalf("ready machine: %d %s", code, wire)
	}
	functionName := "fn-" + strings.ToLower(functionID)
	if code, wire := get(tenantSub, "/v1/apps"); code != http.StatusOK || !strings.Contains(string(wire), functionName) || strings.Contains(string(wire), `"name":"api"`) {
		t.Fatalf("tenant apps: %d %s", code, wire)
	}
	for _, subject := range []string{tenantSub, otherSub} {
		path := "/v1/apps/api/machines"
		if subject == otherSub {
			path = "/v1/apps/" + functionName + "/machines"
		}
		if code, wire := get(subject, path); code != http.StatusNotFound {
			t.Fatalf("foreign app leaked: %d %s", code, wire)
		}
	}
	databaseName := "db-" + strings.ToLower(admitted.DatabaseID)
	expectedAppID := entityid.Derive("manager-database-app", admitted.DatabaseID)
	if admitted.DatabaseID == admitted.CanonicalRoster.DatabaseID {
		t.Fatal("fixture conflated business and canonical database identities")
	}
	genericRuntimeEventually(t, ctx, func() bool {
		code, wire := get(tenantSub, "/v1/apps/"+databaseName+"/machines")
		var body struct {
			Machines []machinesapi.MachineView `json:"machines"`
		}
		if code != http.StatusOK || json.Unmarshal(wire, &body) != nil || len(body.Machines) != len(states) {
			return false
		}
		for _, machine := range body.Machines {
			if machine.AppID != expectedAppID || machine.App != databaseName {
				t.Fatalf("database product identity was not preserved: %+v", machine)
			}
		}
		return true
	})
	if code, wire := get(otherSub, "/v1/apps/"+databaseName); code != http.StatusNotFound {
		t.Fatalf("foreign database leaked: %d %s", code, wire)
	}
	currentMember, err := client.GetService(ctx, &api.GetServiceRequest{ServiceID: memberServiceID})
	if err != nil {
		t.Fatal(err)
	}
	copied := currentMember.Service.Spec.Copy()
	copied.Annotations.Labels["terrascale.database-id"] = admitted.CanonicalRoster.DatabaseID
	changed, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: memberServiceID, ServiceVersion: &currentMember.Service.Meta.Version, Spec: copied})
	if err != nil {
		t.Fatal(err)
	}
	if code, wire := get(tenantSub, "/v1/apps/"+databaseName); code != http.StatusServiceUnavailable {
		t.Fatalf("canonical database replaced business key: %d %s", code, wire)
	}
	if _, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: memberServiceID, ServiceVersion: &changed.Service.Meta.Version, Spec: &currentMember.Service.Spec}); err != nil {
		t.Fatal(err)
	}
	genericRuntimeEventually(t, ctx, func() bool { code, _ := get(tenantSub, "/v1/apps/"+databaseName); return code == http.StatusOK })
	changeDuringProbe.Store(true)
	if code, wire := get(platformSub, "/v1/apps/api/machines"); code != http.StatusServiceUnavailable {
		t.Fatalf("service version changed during probe: %d %s", code, wire)
	}
	genericRuntimeEventually(t, ctx, func() bool { code, _ := get(platformSub, "/v1/apps/api/machines"); return code == http.StatusOK })
	if err := manager.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if code, wire := get(platformSub, "/v1/apps"); code != http.StatusServiceUnavailable {
		t.Fatalf("manager outage became retained inventory: %d %s", code, wire)
	}
	for _, bucket := range []string{"TS_APPS", "TS_MACHINES", "TS_MACHINE_STATUS"} {
		if _, err := broker.JetStream().KeyValue(ctx, bucket); !errors.Is(err, jetstream.ErrBucketNotFound) {
			t.Fatalf("obsolete bucket %s was opened: %v", bucket, err)
		}
	}
}

// Signed material receipts and placement use the actual authority log and
// admitted reader; the object backend and member hosts remain local fixtures.
func machinesAdmittedPlacement(t *testing.T, ctx context.Context, broker *natscell.Runtime, control *authority.Runtime) (placement.Store, placement.Intent, []placement.MemberState) {
	t.Helper()
	epoch := control.Current().Epoch
	_, controllerPrivate := testEd25519(t, t.TempDir(), "machines-material-controller.key")
	baseline := testManagedPlacementIntent()
	spec, recipientSigner := backupAdmissionSpec(t, baseline)
	bundle, err := managedmaterial.GenerateInitial(spec, recipientSigner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	repository, err := managedmaterial.NewRepository(managedmaterial.RepositoryConfig{Region: oci.RegionGRU, Cell: "gru", Namespace: "terrascale", Bucket: "machines-material", KMSKeyID: "ocid1.key.oc1.sa-saopaulo-1.material"}, new(preparationTestObjects), control)
	if err != nil {
		t.Fatal(err)
	}
	object, err := repository.CreateInitial(ctx, epoch, spec.PartitionID, spec, bundle, controllerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := managedmaterial.SignPreparationReceipt("gru", spec.PartitionID, spec, bundle, object, controllerPrivate, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := protocol.EncodeJSON(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.CommitMaterialReceipt(ctx, epoch, spec.PlacementDatabaseID, spec.PartitionID, entityid.Derive("material-receipt", receipt.SpecSHA256), 0, payload); err != nil {
		t.Fatal(err)
	}
	preparation := managedmaterial.PreparationService{Cell: "gru", Repository: repository, Receipts: control, Fencer: control, ControllerKey: controllerPrivate, RecipientSigner: recipientSigner, AllowedSubnetCIDR: "10.0.0.0/24"}
	material := preparedMaterialAdmission(preparation)
	requested := backupAdmissionIntent(t, baseline, receipt)
	policy, privateKey := newPlacementAdmissionPolicy(t)
	payload, err = protocol.EncodeJSON(requested)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	envelope, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{Region: "gru", Kind: "placement.intent", Actor: "ops", OperationID: requested.OperationID(), Generation: requested.Generation, Epoch: epoch}, now, now.Add(time.Minute), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := protocol.EncodeJSON(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyAndApplyPlacement(ctx, wire, "gru", policy, control, material); err != nil {
		t.Fatal(err)
	}
	members, err := placement.NewJetStreamStore(ctx, broker.JetStream(), "gru", 1, admittedPlacementReader{cell: "gru", store: control, material: material})
	if err != nil {
		t.Fatal(err)
	}
	intents, err := members.ListIntents(ctx)
	if err != nil || len(intents) != 1 {
		t.Fatalf("read admitted database placement: %+v %v", intents, err)
	}
	admitted := intents[0]
	states, _, _, _ := managedUpdateAppBaseline(t, admitted, epoch)
	for _, state := range states {
		if _, err := members.CompareAndSwap(ctx, 0, state); err != nil {
			t.Fatal(err)
		}
	}
	return members, admitted, states
}

func signTestAccessToken(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	encode := func(value any) string {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(data)
	}
	signed := encode(map[string]string{"alg": "ES256", "typ": "at+jwt", "kid": kid}) + "." + encode(claims)
	digest := sha256.Sum256([]byte(signed))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// A production controller serves the Machines API only while the adopted
// cell spec carries machines_api, on its broker address, and stops when the
// section goes, without a restart.
func TestMachinesAPIFollowsTheCellSpec(t *testing.T) {
	machinesAPICheck = 50 * time.Millisecond
	t.Cleanup(func() { machinesAPICheck = 5 * time.Second })
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	host := "127.0.0.42"
	auth := newAuthenticatedNATS(t, "gru")
	broker, err := auth.start(t, ctx, natscell.Config{Cell: "gru", Instance: "machines-spec", Replicas: 1,
		Embedded: &natscell.Embedded{Host: host, Port: -1, StoreDir: filepath.Join(t.TempDir(), "nats")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = broker.Close() })
	control, err := authority.Start(ctx, broker.JetStream(), authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Scope: "gru", CandidateID: "0000000000N8R21NWNZ7QZ2X0N", Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	cfg := Config{NATS: natscell.Config{Cell: "gru", Replicas: 1, Embedded: &natscell.Embedded{Host: host}}}
	var current atomic.Pointer[cellspec.MachinesAPI]
	loopCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		done <- machinesAPILoop(loopCtx, cfg, broker, control, func() bool { return true }, current.Load, &managerMachinesView{}, nil)
	}()
	health := func() int {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://%s:%d/healthz", host, cellspec.MachinesAPIPort), nil)
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			return 0
		}
		response.Body.Close()
		return response.StatusCode
	}
	await := func(want int) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); health() != want; {
			if time.Now().After(deadline) {
				t.Fatalf("health %d, want %d", health(), want)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	await(0)
	current.Store(&cellspec.MachinesAPI{Issuer: "https://gru.auth.terrascale.tech/terrascale", Audience: "https://gru.orch.terrascale.tech",
		JWKSURLs: []string{"http://127.0.0.1:1/jwks.json"}, Clients: []string{"00000000000000000000000001"}})
	await(http.StatusOK)
	current.Store(nil)
	await(0)
	stop()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
