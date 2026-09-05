package vmqual

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

type admissionNetwork struct {
	smokeFakeNetwork
	plan vmnet.NetworkPlan
}

func (n *admissionNetwork) Plan() vmnet.NetworkPlan { return n.plan }
func (n *admissionNetwork) Journal() vmnet.Journal  { return n.plan.Journal }

type admissionFactory struct {
	smokeFakeFactory
	journalPath   string
	observedPlans []Journal
}

func (f *admissionFactory) Create(ctx context.Context, guest Guest) (VM, error) {
	if guest.Region == FourthRegion {
		journal, err := readJournal(f.journalPath)
		if err != nil {
			return nil, err
		}
		if len(journal.VMs) != 8 {
			return nil, errors.New("new host created before both admission intents were durable")
		}
		f.observedPlans = append(f.observedPlans, journal)
	}
	return f.smokeFakeFactory.Create(ctx, guest)
}

func admissionFixture(t *testing.T, fourth bool) (*Stack, *admissionFactory, *admissionNetwork) {
	t.Helper()
	root, toolsRoot := t.TempDir(), t.TempDir()
	tools := map[string]string{}
	for _, name := range []string{"ip", "nft", "tc", "sysctl"} {
		path := filepath.Join(toolsRoot, name)
		if err := os.WriteFile(path, []byte("test executable"), 0700); err != nil {
			t.Fatal(err)
		}
		tools[name] = path
	}
	config := vmnet.DefaultConfig()
	sum := sha256.Sum256([]byte(root))
	config.RunID = hex.EncodeToString(sum[:16])
	config.CoordinationRoot = filepath.Join(root, "coordination")
	config.Tools = vmnet.ToolPaths{IP: tools["ip"], NFT: tools["nft"], TC: tools["tc"], Sysctl: tools["sysctl"]}
	if fourth {
		config.Regions = append(config.Regions, vmnet.RegionSpec{Code: FourthRegion, Guests: []vmnet.GuestSpec{{ID: "iad-member-1"}, {ID: "iad-member-2"}}})
	}
	plan, err := vmnet.Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	network := &admissionNetwork{plan: plan}
	factory := &admissionFactory{journalPath: filepath.Join(root, "cleanup.json")}
	stack, err := NewStack(StackConfig{Guests: LaunchGuests(256), VMFactory: factory, Network: network, StateRoot: filepath.Join(root, "state"), JournalPath: factory.journalPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stack.Cleanup(context.Background()) })
	return stack, factory, network
}

func TestRegionAdmissionJournalsBothHostsBeforeCreateAndPreservesR3(t *testing.T) {
	stack, factory, _ := admissionFixture(t, true)
	if err := stack.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := stack.Snapshot()
	if len(factory.created) != 6 {
		t.Fatal("predeclared IAD slots booted before admission")
	}
	if err := stack.AdmitRegion(context.Background(), FourthRegionGuests(256)); err != nil {
		t.Fatal(err)
	}
	after := stack.Snapshot()
	if !after.Started || len(after.Guests) != 8 || len(after.VMs) != 8 || len(factory.observedPlans) != 2 {
		t.Fatalf("incomplete admission: %+v plans=%d", after, len(factory.observedPlans))
	}
	if !reflect.DeepEqual(before.Guests, after.Guests[:6]) {
		t.Fatal("admission changed permanent replica topology")
	}
	for _, guest := range after.Guests[6:] {
		if guest.Control || !guest.Service {
			t.Fatal("admitted host is not a local service member")
		}
		observation, err := after.VMs[guest.ID].Inspect(context.Background())
		if err != nil || !observation.Running || !observation.Ready || observation.Region != FourthRegion {
			t.Fatalf("admitted host is not live: %+v, %v", observation, err)
		}
	}
	if err := stack.AdmitRegion(context.Background(), FourthRegionGuests(256)); err != nil {
		t.Fatal(err)
	}
	if len(factory.created) != 8 || len(stack.ResourceReport().VMs) != 8 {
		t.Fatal("duplicate admission recreated guests or omitted resource observations")
	}
	if err := stack.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, vm := range factory.created {
		if !vm.deleted {
			t.Fatal("cleanup stranded an admitted host")
		}
	}
}

func TestRegionAdmissionRefusesPrematureForeignAndUnplannedHosts(t *testing.T) {
	stack, factory, _ := admissionFixture(t, true)
	if err := stack.AdmitRegion(context.Background(), FourthRegionGuests(256)); err == nil {
		t.Fatal("admitted IAD before baseline readiness")
	}
	if err := stack.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, alter := range []func([]Guest){
		func(g []Guest) { g[0].Control = true },
		func(g []Guest) { g[1].Service = false },
		func(g []Guest) { g[0].ID = "foreign-host" },
		func(g []Guest) { g[1].Region = "AMS" },
	} {
		guests := FourthRegionGuests(256)
		alter(guests)
		if err := stack.AdmitRegion(context.Background(), guests); err == nil {
			t.Fatal("accepted invalid admission")
		}
	}
	if len(factory.created) != 6 {
		t.Fatal("rejected admission created a host")
	}
	unplanned, _, _ := admissionFixture(t, false)
	if err := unplanned.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := unplanned.AdmitRegion(context.Background(), FourthRegionGuests(256)); err == nil {
		t.Fatal("admitted guests without owned network slots")
	}
}

func TestRegionAdmissionFailureCleansBothNewIntentsAndBaseline(t *testing.T) {
	stack, factory, _ := admissionFixture(t, true)
	if err := stack.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("local orchestrator never became active")
	factory.configure = func(vm *smokeFakeVM) {
		if vm.guest.ID == "iad-member-2" {
			vm.startErr = failure
		}
	}
	err := stack.AdmitRegion(context.Background(), FourthRegionGuests(256))
	if !errors.Is(err, failure) {
		t.Fatalf("activation failure = %v", err)
	}
	if len(factory.observedPlans) != 2 || len(stack.Snapshot().VMs) != 0 {
		t.Fatal("failed admission lost durable intent or retained handles")
	}
	for _, vm := range factory.created {
		if !vm.deleted {
			t.Fatal("failed admission stranded a VM")
		}
	}
	if _, err := os.Stat(factory.journalPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed admission cleanup journal remains: %v", err)
	}
}

func TestFourthRegionCleanupRequiresDeclaredOwnedNetworkAndBothHosts(t *testing.T) {
	stack, _, _ := admissionFixture(t, true)
	if err := stack.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := stack.AdmitRegion(context.Background(), FourthRegionGuests(256)); err != nil {
		t.Fatal(err)
	}
	original, err := readJournal(stack.Config().JournalPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateJournal(original); err != nil {
		t.Fatal(err)
	}
	_, _, network := admissionFixture(t, false)
	missingNetwork := cloneJournal(original)
	missingNetwork.Network = network.plan.Journal
	if err := validateJournal(missingNetwork); err == nil || !strings.Contains(err.Error(), "invalid identity") {
		t.Fatalf("foreign namespace was accepted for IAD cleanup: %v", err)
	}
	forgedRegion := cloneJournal(missingNetwork)
	forgedRegion.VMs[6].Region, forgedRegion.VMs[7].Region = string(vmnet.GRU), string(vmnet.GRU)
	if err := validateJournal(forgedRegion); err == nil {
		t.Fatal("IAD host identities bypassed ownership by claiming a launch region")
	}
	missingPeer := cloneJournal(original)
	missingPeer.VMs = missingPeer.VMs[:7]
	if err := validateJournal(missingPeer); err == nil {
		t.Fatal("cleanup discarded the second IAD host obligation")
	}
	foreignHost := cloneJournal(original)
	foreignHost.VMs[6].ID = "another-owner"
	if err := validateJournal(foreignHost); err == nil {
		t.Fatal("cleanup accepted an undeclared fourth-region host")
	}
}

func TestRegionAdmissionCannotRaiseTheResourceBudget(t *testing.T) {
	stack, factory, _ := admissionFixture(t, true)
	stack.config.MaxRSSBytes = 7 * 256 << 20
	if err := stack.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := stack.AdmitRegion(context.Background(), FourthRegionGuests(256)); err == nil {
		t.Fatal("admission silently exceeded the declared budget")
	}
	if len(factory.created) != 6 {
		t.Fatal("over-budget admission created hosts")
	}
	journal, err := readJournal(factory.journalPath)
	if err != nil || len(journal.VMs) != 6 {
		t.Fatalf("over-budget admission changed durable topology: %+v %v", journal, err)
	}
}
