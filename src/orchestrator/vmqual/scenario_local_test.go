package vmqual

import (
	"context"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
)

type scenarioTestVM struct{ guest Guest }

func (v scenarioTestVM) StartReady(context.Context) error { return nil }
func (v scenarioTestVM) Stop(context.Context) error       { return nil }
func (v scenarioTestVM) Delete(context.Context) error     { return nil }
func (v scenarioTestVM) Inspect(context.Context) (VMObservation, error) {
	return VMObservation{ID: v.guest.ID, Region: v.guest.Region, Running: true, Ready: true, MemoryMiB: v.guest.MemoryMiB}, nil
}

type scenarioTestFactory struct{}

func (scenarioTestFactory) Create(_ context.Context, guest Guest) (VM, error) {
	return scenarioTestVM{guest: guest}, nil
}

type scenarioTestNetwork struct{}

func (scenarioTestNetwork) Apply(context.Context) error   { return nil }
func (scenarioTestNetwork) Cleanup(context.Context) error { return nil }

func TestLocalScenarioJourneyUsesAllProviderEndpoints(t *testing.T) {
	providers, err := NewLocalProviderEndpoints(LocalProviderConfig{StateRoot: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer providers.Close()
	driver, err := providers.LocalScenarioDriver()
	if err != nil {
		t.Fatal(err)
	}
	stack, err := NewStack(StackConfig{
		Guests:      LaunchGuests(256),
		VMFactory:   scenarioTestFactory{},
		Network:     scenarioTestNetwork{},
		StateRoot:   t.TempDir(),
		JournalPath: t.TempDir() + "/cleanup.json",
	})
	if err != nil {
		t.Fatal(err)
	}
	report, err := RunSuite(context.Background(), stack, driver)
	if err != nil {
		t.Fatalf("local suite failed: %v\nreport=%+v\nevidence=%+v", err, report, driver.Evidence())
	}
	if !report.OK() || len(driver.Completed()) != len(RequiredScenarios) {
		t.Fatalf("report not complete: ok=%v completed=%v", report.OK(), driver.Completed())
	}
	if len(driver.Evidence()) < len(RequiredScenarios) {
		t.Fatalf("evidence count=%d", len(driver.Evidence()))
	}
}

func TestLocalScenarioDriverRejectsOutOfOrderProof(t *testing.T) {
	providers, err := NewLocalProviderEndpoints(LocalProviderConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer providers.Close()
	driver, err := providers.LocalScenarioDriver()
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.Run(context.Background(), ScenarioR3); err == nil {
		t.Fatal("out-of-order R3 was accepted")
	}
	if got := driver.Completed(); len(got) != 0 {
		t.Fatalf("completed after rejected scenario = %v", got)
	}
	if got := vmnet.StableCIDR(vmnet.GRU); got == "" {
		t.Fatal("GRU topology is not configured")
	}
}
