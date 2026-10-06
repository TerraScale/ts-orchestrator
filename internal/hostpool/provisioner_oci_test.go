package hostpool

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
)

type ociFailure struct {
	status int
	code   string
}

func (e ociFailure) Error() string           { return e.code }
func (e ociFailure) GetHTTPStatusCode() int  { return e.status }
func (e ociFailure) GetMessage() string      { return e.code }
func (e ociFailure) GetCode() string         { return e.code }
func (e ociFailure) GetOpcRequestID() string { return "test" }

// fakeCompute is OCI: a launch that does not fail adds an instance.
type fakeCompute struct {
	instances  []core.Instance
	launches   []core.LaunchInstanceRequest
	terminated []string
	launchErr  error
	created    bool // a failing launch still created its instance
	pages      int
	// held is set while a launch admission holds the cell spec;
	// heldAtLaunch records it for each launch.
	held         bool
	heldAtLaunch []bool
}

func (f *fakeCompute) ListInstances(_ context.Context, request core.ListInstancesRequest) (core.ListInstancesResponse, error) {
	var items []core.Instance
	for _, instance := range f.instances {
		if request.DisplayName == nil || *request.DisplayName == *instance.DisplayName {
			items = append(items, instance)
		}
	}
	// Serve one instance per page so listing follows pages.
	f.pages++
	if request.Page != nil || len(items) < 2 {
		if request.Page != nil {
			items = items[1:]
		}
		return core.ListInstancesResponse{Items: items}, nil
	}
	return core.ListInstancesResponse{Items: items[:1], OpcNextPage: common.String("next")}, nil
}

func (f *fakeCompute) LaunchInstance(_ context.Context, request core.LaunchInstanceRequest) (core.LaunchInstanceResponse, error) {
	f.launches = append(f.launches, request)
	f.heldAtLaunch = append(f.heldAtLaunch, f.held)
	if f.launchErr == nil || f.created {
		details := request.LaunchInstanceDetails
		f.instances = append(f.instances, core.Instance{Id: common.String("ocid1.instance.oc1..new"),
			DisplayName: details.DisplayName, LifecycleState: core.InstanceLifecycleStateProvisioning,
			FreeformTags: details.FreeformTags, TimeCreated: &common.SDKTime{Time: now}})
	}
	if f.launchErr != nil {
		failure, _ := f.launchErr.(ociFailure)
		return core.LaunchInstanceResponse{RawResponse: &http.Response{StatusCode: failure.status}}, f.launchErr
	}
	return core.LaunchInstanceResponse{}, nil
}

func (f *fakeCompute) TerminateInstance(_ context.Context, request core.TerminateInstanceRequest) (core.TerminateInstanceResponse, error) {
	if request.PreserveBootVolume == nil || *request.PreserveBootVolume {
		return core.TerminateInstanceResponse{}, errors.New("boot volume kept")
	}
	f.terminated = append(f.terminated, *request.InstanceId)
	return core.TerminateInstanceResponse{}, nil
}

type memoryJournal map[string]LaunchRecord

func (j memoryJournal) Read(_ context.Context, node string) (LaunchRecord, bool, error) {
	record, ok := j[node]
	return record, ok, nil
}
func (j memoryJournal) Write(_ context.Context, node string, record LaunchRecord) error {
	j[node] = record
	return nil
}
func (j memoryJournal) Delete(_ context.Context, node string) error {
	delete(j, node)
	return nil
}

func poolHost(id, node, pool, cell string, state core.InstanceLifecycleStateEnum) core.Instance {
	return core.Instance{Id: common.String(id), DisplayName: common.String(node), LifecycleState: state,
		FreeformTags: map[string]string{tagCell: cell, tagPool: pool}, TimeCreated: &common.SDKTime{Time: now}}
}

func ociPool() NodePool {
	pool := generalPool()
	pool.Shape.MemoryBytes, pool.Shape.DiskBytes = 12<<30, 60<<30
	pool.FailureDomains = []string{"fault-domain-1", "fault-domain-2"}
	return pool
}

// newProvisioner launches spec version v1's image; admitted counts the
// launches admitted under it and held is set while an admission holds the
// cell spec.
func newProvisioner(compute *fakeCompute, clock *time.Time) (*OCIProvisioner, memoryJournal, *int) {
	journal, admitted := memoryJournal{}, 0
	provisioner := &OCIProvisioner{Cell: "gru", Region: "GRU", Compute: compute, Journal: journal,
		Template: OCITemplate{CompartmentID: "ocid1.compartment.oc1..c", AvailabilityDomain: "AD-1",
			SubnetID: "ocid1.subnet.oc1..s", NetworkSecurityGroupIDs: []string{"ocid1.nsg.oc1..n"},
			Shape: "VM.Standard.A1.Flex", BootVolumeVPUsPerGB: 10,
			Metadata: map[string]string{hostboot.EnrollmentMetadataKey: "bundle"}},
		Image: func(context.Context) (string, string, error) { return "ocid1.image.oc1..i", "v1", nil },
		Now:   func() time.Time { return *clock }}
	provisioner.Admit = func(_ context.Context, image, version string) (func(), error) {
		if image != "ocid1.image.oc1..i" || version != "v1" || compute.held {
			return nil, errors.New("not admitted")
		}
		admitted++
		compute.held = true
		return func() { compute.held = false }, nil
	}
	return provisioner, journal, &admitted
}

var firstHost = Launch{Node: "gru-1-pool-general-1", FailureDomain: "fault-domain-2"}

func TestOCIProvisionerLaunchesAQualifiedTaggedHost(t *testing.T) {
	clock := now
	compute := &fakeCompute{}
	provisioner, journal, admitted := newProvisioner(compute, &clock)
	if err := provisioner.Launch(context.Background(), 3, ociPool(), firstHost); err != nil {
		t.Fatal(err)
	}
	// The launch ran under its admission, which was released afterwards.
	if len(compute.launches) != 1 || *admitted != 1 || !compute.heldAtLaunch[0] || compute.held {
		t.Fatalf("launches %d, admissions %d, held at launch %v, still held %v", len(compute.launches), *admitted,
			compute.heldAtLaunch, compute.held)
	}
	request := compute.launches[0]
	details := request.LaunchInstanceDetails
	source, _ := details.SourceDetails.(core.InstanceSourceViaImageDetails)
	descriptor, err := hostboot.ParseHost([]byte(details.Metadata[hostboot.MetadataKey]))
	if err != nil || descriptor != hostboot.Static("gru", "GRU", "gru-1-pool-general-1") {
		t.Fatalf("boot descriptor %+v, %v", descriptor, err)
	}
	if *details.DisplayName != "gru-1-pool-general-1" || *details.FaultDomain != "FAULT-DOMAIN-2" ||
		*details.ShapeConfig.Ocpus != 4 || *details.ShapeConfig.MemoryInGBs != 12 || *source.BootVolumeSizeInGBs != 60 ||
		*source.ImageId != "ocid1.image.oc1..i" || *details.CreateVnicDetails.AssignPublicIp ||
		*details.CreateVnicDetails.HostnameLabel != "gru-1-pool-general-1" ||
		details.Metadata[hostboot.EnrollmentMetadataKey] != "bundle" ||
		details.FreeformTags[tagCell] != "gru" || details.FreeformTags[tagPool] != "general" ||
		details.FreeformTags[tagLaunchToken] != *request.OpcRetryToken ||
		journal[firstHost.Node].Token != *request.OpcRetryToken || request.RequestMetadata.RetryPolicy == nil {
		t.Fatalf("launch request %+v", request)
	}
	// OCI holds it now: a second launch does nothing.
	if err := provisioner.Launch(context.Background(), 3, ociPool(), firstHost); err != nil || len(compute.launches) != 1 {
		t.Fatalf("relaunch: %d launches, %v", len(compute.launches), err)
	}
}

// A launch whose outcome is unknown replays its exact request and token,
// even after the pool changed; only a fresh launch's single refused
// attempt, or a token past OCI's replay window with no host listed, lets
// a new token be minted. A host never launches twice.
func TestOCIProvisionerReplaysUncertainLaunches(t *testing.T) {
	clock := now
	compute := &fakeCompute{launchErr: errors.New("connection reset")}
	provisioner, journal, _ := newProvisioner(compute, &clock)
	var admitted []string
	admit := provisioner.Admit
	provisioner.Admit = func(ctx context.Context, image, version string) (func(), error) {
		admitted = append(admitted, version)
		return admit(ctx, image, "v1")
	}
	changed := ociPool()
	changed.Shape.CPU = 2
	for _, pool := range []NodePool{ociPool(), changed} {
		if err := provisioner.Launch(context.Background(), 3, pool, firstHost); err == nil {
			t.Fatal("a failed launch succeeded")
		}
	}
	first, replay := compute.launches[0], compute.launches[1]
	if *first.OpcRetryToken != *replay.OpcRetryToken || *replay.ShapeConfig.Ocpus != 4 ||
		journal[firstHost.Node].Attempts != 2 || admitted[0] != "v1" || admitted[1] != "" {
		t.Fatalf("replay sent %v OCPUs with token %s after %s (attempts %d, admitted %v)", *replay.ShapeConfig.Ocpus,
			*replay.OpcRetryToken, *first.OpcRetryToken, journal[firstHost.Node].Attempts, admitted)
	}
	// A refused replay proves nothing about the first request.
	compute.launchErr = ociFailure{429, "TooManyRequests"}
	_ = provisioner.Launch(context.Background(), 3, ociPool(), firstHost)
	if record, kept := journal[firstHost.Node]; !kept || record.Token != *first.OpcRetryToken {
		t.Fatal("a refused replay forgot an uncertain launch")
	}
	// Past OCI's replay window, with no host listed, a new token.
	clock = clock.Add(replayWindow)
	compute.launchErr = errors.New("connection reset")
	_ = provisioner.Launch(context.Background(), 3, ociPool(), firstHost)
	if *compute.launches[3].OpcRetryToken == *first.OpcRetryToken || journal[firstHost.Node].Attempts != 1 {
		t.Fatal("an expired launch replayed its token")
	}
	// A fresh launch whose only attempt OCI refused forgets its token.
	delete(journal, firstHost.Node)
	compute.launchErr = ociFailure{400, "LimitExceeded"}
	if err := provisioner.Launch(context.Background(), 3, ociPool(), firstHost); err == nil {
		t.Fatal("a rejected launch succeeded")
	}
	if _, kept := journal[firstHost.Node]; kept {
		t.Fatal("a refused fresh launch kept its token")
	}
	// A failed launch that still created its host is adopted.
	compute.launchErr, compute.created = errors.New("timeout"), true
	_ = provisioner.Launch(context.Background(), 3, ociPool(), firstHost)
	if err := provisioner.Launch(context.Background(), 3, ociPool(), firstHost); err != nil || len(compute.launches) != 6 {
		t.Fatalf("created host relaunched: %d launches, %v", len(compute.launches), err)
	}
}

// A frozen request survives the journal exactly, launch material included.
func TestLaunchRequestsRoundTripExactly(t *testing.T) {
	clock := now
	provisioner, _, _ := newProvisioner(&fakeCompute{}, &clock)
	details, err := provisioner.details(ociPool(), firstHost, "ocid1.image.oc1..i")
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encodeRequest(details)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeRequest(wire); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeRequest(append(wire[:len(wire)-1:len(wire)-1], []byte(`,"unknown":1}`)...)); err == nil {
		t.Fatal("a request that does not round-trip was replayed")
	}
}

func TestOCIProvisionerRefuses(t *testing.T) {
	clock := now
	for name, test := range map[string]struct {
		held   []core.Instance
		pool   func(*NodePool)
		launch Launch
		setup  func(*OCIProvisioner)
	}{
		"not a pool host":     {launch: Launch{Node: "gru-1-db-1", FailureDomain: "fault-domain-1"}},
		"another cell's host": {launch: Launch{Node: "sfo-1-pool-general-1", FailureDomain: "fault-domain-1"}},
		"no OCI fault domain": {launch: Launch{Node: firstHost.Node, FailureDomain: "fd-1"}},
		"untagged name holder": {launch: firstHost, held: []core.Instance{{Id: common.String("ocid1.instance.oc1..x"),
			DisplayName: common.String(firstHost.Node), LifecycleState: core.InstanceLifecycleStateRunning}}},
		"another pool's host": {launch: firstHost,
			held: []core.Instance{poolHost("ocid1.instance.oc1..x", firstHost.Node, "web", "gru", core.InstanceLifecycleStateRunning)}},
		"still terminating": {launch: firstHost,
			held: []core.Instance{poolHost("ocid1.instance.oc1..x", firstHost.Node, "general", "gru", core.InstanceLifecycleStateTerminating)}},
		"unqualified image": {launch: firstHost, setup: func(p *OCIProvisioner) {
			p.Image = func(context.Context) (string, string, error) { return "", "", errors.New("image receipt mismatch") }
		}},
		"spec changed before the launch": {launch: firstHost, setup: func(p *OCIProvisioner) {
			p.Image = func(context.Context) (string, string, error) { return "ocid1.image.oc1..i", "v0", nil }
		}},
		"reserved metadata": {launch: firstHost, setup: func(p *OCIProvisioner) {
			p.Template.Metadata = map[string]string{hostboot.MetadataKey: "{}"}
		}},
		"fractional memory": {launch: firstHost, pool: func(p *NodePool) { p.Shape.MemoryBytes += 1 << 20 }},
		"small disk":        {launch: firstHost, pool: func(p *NodePool) { p.Shape.DiskBytes = 10 << 30 }},
	} {
		compute := &fakeCompute{instances: test.held}
		provisioner, _, _ := newProvisioner(compute, &clock)
		if test.setup != nil {
			test.setup(provisioner)
		}
		pool := ociPool()
		if test.pool != nil {
			test.pool(&pool)
		}
		if err := provisioner.Launch(context.Background(), 3, pool, test.launch); err == nil || len(compute.launches) != 0 {
			t.Errorf("%s: launched (%v)", name, err)
		}
	}
}

func TestOCIProvisionerReclaimsOnlyItsPoolHosts(t *testing.T) {
	clock := now
	compute := &fakeCompute{instances: []core.Instance{
		poolHost("ocid1.instance.oc1..a", "gru-1-pool-general-1", "general", "gru", core.InstanceLifecycleStateRunning),
		poolHost("ocid1.instance.oc1..b", "gru-1-pool-general-2", "general", "gru", core.InstanceLifecycleStateTerminating),
		poolHost("ocid1.instance.oc1..c", "gru-1-pool-general-3", "general", "gru", core.InstanceLifecycleStateTerminated),
		{Id: common.String("ocid1.instance.oc1..d"), DisplayName: common.String("gru-1-pool-general-4"),
			LifecycleState: core.InstanceLifecycleStateRunning},
	}}
	provisioner, journal, _ := newProvisioner(compute, &clock)
	journal["gru-1-pool-general-1"] = LaunchRecord{Token: "t"}
	for _, node := range []string{"gru-1-pool-general-1", "gru-1-pool-general-2", "gru-1-pool-general-3"} {
		if err := provisioner.Reclaim(context.Background(), 3, ociPool(), node); err != nil {
			t.Fatalf("reclaim %s: %v", node, err)
		}
	}
	if len(compute.terminated) != 1 || compute.terminated[0] != "ocid1.instance.oc1..a" || len(journal) != 0 {
		t.Fatalf("terminated %v, journal %v", compute.terminated, journal)
	}
	for _, node := range []string{"gru-1-pool-general-4", "gru-1-db-1"} {
		if err := provisioner.Reclaim(context.Background(), 3, ociPool(), node); err == nil {
			t.Errorf("reclaimed %s", node)
		}
	}
	if len(compute.terminated) != 1 {
		t.Fatalf("terminated a host that is not this cell's pool host: %v", compute.terminated)
	}
}

func TestOCIProvisionerListsTheCellsPoolHosts(t *testing.T) {
	clock := now
	compute := &fakeCompute{instances: []core.Instance{
		poolHost("ocid1.instance.oc1..a", "gru-1-pool-general-1", "general", "gru", core.InstanceLifecycleStateRunning),
		poolHost("ocid1.instance.oc1..b", "gru-1-pool-web-1", "web", "gru", core.InstanceLifecycleStateTerminating),
		poolHost("ocid1.instance.oc1..c", "gru-1-pool-general-2", "general", "gru", core.InstanceLifecycleStateTerminated),
		poolHost("ocid1.instance.oc1..d", "sfo-1-pool-general-1", "general", "sfo", core.InstanceLifecycleStateRunning),
		{Id: common.String("ocid1.instance.oc1..e"), DisplayName: common.String("gru-1-ctl-1"),
			LifecycleState: core.InstanceLifecycleStateRunning},
	}}
	provisioner, _, _ := newProvisioner(compute, &clock)
	instances, err := provisioner.Instances(context.Background())
	if err != nil || len(instances) != 2 || compute.pages < 2 ||
		instances[0] != (Instance{Node: "gru-1-pool-general-1", Pool: "general", Created: now}) ||
		instances[1] != (Instance{Node: "gru-1-pool-web-1", Pool: "web", Created: now, Terminating: true}) {
		t.Fatalf("instances %+v (%d pages), %v", instances, compute.pages, err)
	}
	for name, held := range map[string]core.Instance{
		"tagged host without a pool name": poolHost("ocid1.instance.oc1..f", "gru-1-ctl-2", "general", "gru",
			core.InstanceLifecycleStateRunning),
		"two live hosts with one name": poolHost("ocid1.instance.oc1..g", "gru-1-pool-general-1", "general", "gru",
			core.InstanceLifecycleStateRunning),
	} {
		compute := &fakeCompute{instances: append(append([]core.Instance(nil), compute.instances...), held)}
		provisioner, _, _ := newProvisioner(compute, &clock)
		if _, err := provisioner.Instances(context.Background()); err == nil {
			t.Errorf("%s: listed", name)
		}
	}
}

func TestKVLaunchJournal(t *testing.T) {
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := OpenLaunchJournal(t.Context(), js, 1)
	if err != nil {
		t.Fatal(err)
	}
	record := LaunchRecord{Token: "token", Request: []byte(`{"displayName":"gru-1-pool-general-1"}`), Minted: now, Attempts: 2}
	if err := journal.Write(t.Context(), firstHost.Node, record); err != nil {
		t.Fatal(err)
	}
	if got, found, err := journal.Read(t.Context(), firstHost.Node); err != nil || !found || !got.Minted.Equal(now) ||
		got.Token != record.Token || string(got.Request) != string(record.Request) || got.Attempts != 2 {
		t.Fatalf("read %+v, %v, %v", got, found, err)
	}
	for range 2 {
		if err := journal.Delete(t.Context(), firstHost.Node); err != nil {
			t.Fatal(err)
		}
	}
	if _, found, err := journal.Read(t.Context(), firstHost.Node); err != nil || found {
		t.Fatalf("deleted record read back: %v, %v", found, err)
	}
	if _, err := OpenLaunchJournal(t.Context(), nil, 1); err == nil {
		t.Fatal("a journal without JetStream opened")
	}
}
