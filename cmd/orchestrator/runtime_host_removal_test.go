package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/hostremoval"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

func TestRemovalRuntimeBindsSPIFFEToExactOCIResourcePerInvocation(t *testing.T) {
	first := ocireconcile.ObservedMember{ID: "ocid1.instance.first", Region: "gru", Index: 1}
	second := ocireconcile.ObservedMember{ID: "ocid1.instance.second", Region: "gru", Index: 2}
	observed := hostremoval.MemberObservation{Identity: "spiffe://terrascale.tech/prod/member/one", Region: "gru", Slot: 1, Generation: 4}
	var terminated string
	runtime := &productionHostRemoval{
		owner:       &hostremoval.Owner{},
		terminateFn: func(_ context.Context, id, etag string) error { terminated = id; return nil },
		observeFn: func(_ context.Context, member ocireconcile.ObservedMember) (hostremoval.MemberObservation, error) {
			if member.ID != first.ID {
				t.Fatalf("wrong exact observation: %s", member.ID)
			}
			return observed, nil
		},
	}
	bound := runtime.ownerFor(first, observed)
	other := runtime.ownerFor(second, hostremoval.MemberObservation{Identity: "spiffe://terrascale.tech/prod/member/two", Generation: 4})
	if present, err := bound.Observe(t.Context(), observed.Identity); err != nil || !present {
		t.Fatalf("observation: %v", err)
	}
	if err := bound.Terminate(t.Context(), observed.Identity); err != nil || terminated != first.ID {
		t.Fatalf("termination resource=%s error=%v", terminated, err)
	}
	if err := other.Terminate(t.Context(), observed.Identity); !errors.Is(err, hostremoval.ErrConflict) {
		t.Fatalf("cross invocation identity accepted: %v", err)
	}
	observed.Generation++
	if _, err := bound.Observe(t.Context(), observed.Identity); !errors.Is(err, hostremoval.ErrConflict) {
		t.Fatalf("changed generation accepted: %v", err)
	}
}

type runtimeRemovalJournal struct {
	record hostremoval.Operation
	found  bool
}

func (j *runtimeRemovalJournal) Load(context.Context, string) (hostremoval.Operation, error) {
	if !j.found {
		return hostremoval.Operation{}, hostremoval.ErrMissing
	}
	return j.record, nil
}
func (j *runtimeRemovalJournal) Reserve(_ context.Context, op string, m hostremoval.MemberObservation, generation uint64, s []hostremoval.MemberObservation) (hostremoval.Operation, error) {
	if j.found {
		return j.record, nil
	}
	request := hostremoval.RemovalRequest{OperationID: op, Member: m, Generation: generation, Survivors: s}
	j.record = hostremoval.Operation{OperationID: op, ProviderETag: m.ProviderETag, ResourceID: m.ResourceID, MemberIdentity: m.Identity, Generation: generation, Survivors: s, Stage: hostremoval.StageInventoryPending, PendingRequest: &request}
	j.found = true
	return j.record, nil
}

func (j *runtimeRemovalJournal) Begin(_ context.Context, op string, m hostremoval.MemberObservation, generation, revision uint64, r []hostremoval.Replacement, s []hostremoval.MemberObservation) (hostremoval.Operation, error) {
	j.record = hostremoval.Operation{OperationID: op, ProviderETag: m.ProviderETag, ResourceID: m.ResourceID, MemberIdentity: m.Identity, Generation: generation, InventoryRevision: revision, Replacements: r, Survivors: s, Stage: hostremoval.StageInventoryCaptured}
	j.found = true
	return j.record, nil
}
func (j *runtimeRemovalJournal) Advance(_ context.Context, _ string, stage hostremoval.Stage) (hostremoval.Operation, error) {
	j.record.Stage = stage
	return j.record, nil
}

type runtimeRemovalGateway struct {
	ocireconcile.ComputeGateway
	current      ocireconcile.ObservedMember
	terminal     bool
	failure      error
	terminations int
}

func (g *runtimeRemovalGateway) ObserveMember(_ context.Context, id string) (ocireconcile.ObservedMember, error) {
	if id != g.current.ID {
		return ocireconcile.ObservedMember{}, errors.New("unknown resource")
	}
	if g.failure != nil {
		return ocireconcile.ObservedMember{}, g.failure
	}
	if g.terminal {
		g.current.LifecycleState = "TERMINATED"
		return g.current, ocireconcile.ErrMemberTerminated
	}
	return g.current, nil
}
func (g *runtimeRemovalGateway) TerminateMember(_ context.Context, id, etag string) error {
	if id != g.current.ID {
		return errors.New("wrong resource")
	}
	if g.terminal {
		g.terminations++
		return errors.New("duplicate termination mutation")
	}
	g.terminations++
	g.terminal = true
	return errors.New("OCI deleted instance but response was lost")
}

type runtimeRemovalOwnership struct {
	provider.DurableOwnershipEvidence
	record provider.ProviderOwnershipRecord
	reads  int
}

func (o *runtimeRemovalOwnership) AuthoritativeDurable() bool { return true }
func (o *runtimeRemovalOwnership) Lookup(_ context.Context, id provider.ProviderResourceId) (provider.ProviderOwnershipRecord, bool, error) {
	o.reads++
	return o.record, id.Value == o.record.ResourceId.Value, nil
}

func TestRemovalRuntimeRestartAfterLostTerminationResponse(t *testing.T) {
	member := ocireconcile.ObservedMember{ID: "ocid1.instance.original", ETag: "etag", CompartmentID: "compartment", Region: "gru", Index: 1, LifecycleState: "RUNNING"}
	gateway := &runtimeRemovalGateway{current: member}
	ownership := &runtimeRemovalOwnership{record: provider.ProviderOwnershipRecord{ResourceId: provider.ProviderResourceId{Value: member.ID}, CompartmentId: provider.ProviderCompartmentId{Value: member.CompartmentID}, CellId: provider.ProviderCellId{Value: "gru"}, Generation: provider.ProviderGeneration{Value: 7}, ServerIdentity: "spiffe://terrascale.tech/prod/member/original"}}
	journal := &runtimeRemovalJournal{}
	construct := func() *productionHostRemoval {
		return &productionHostRemoval{observeFn: newProductionDurableMemberObserver(ownership, gateway), terminateFn: newProductionOCITerminator(map[string]ocireconcile.ComputeGateway{"gru": gateway}), owner: &hostremoval.Owner{Journal: journal,
			Inventory: func(context.Context, hostremoval.RemovalRequest, []hostremoval.Replacement) (uint64, []hostremoval.Replacement, error) {
				return 1, nil, nil
			},
			Replace:    func(context.Context, hostremoval.Replacement) error { return nil },
			Revalidate: func(context.Context, string, string, uint64) error { return nil },
			Fence:      func(context.Context, string, string, []hostremoval.Replacement) error { return nil },
		}}
	}
	if err := construct().RemoveMember(t.Context(), "remove", member, nil); err == nil {
		t.Fatal("lost response must remain pending")
	}
	if journal.record.Stage != hostremoval.StageFenced || gateway.terminations != 1 {
		t.Fatalf("first attempt: %+v calls=%d", journal.record, gateway.terminations)
	}
	unavailable := errors.New("OCI 404: unauthorized or not found")
	gateway.failure = unavailable
	if err := construct().RemoveMember(t.Context(), "remove", member, nil); !errors.Is(err, unavailable) {
		t.Fatalf("ambiguous absence accepted: %v", err)
	}
	if journal.record.Stage != hostremoval.StageFenced {
		t.Fatal("unavailable provider completed journal")
	}
	gateway.failure = nil
	ownership.record.Generation.Value++
	if err := construct().RemoveMember(t.Context(), "remove", member, nil); !errors.Is(err, hostremoval.ErrConflict) {
		t.Fatalf("rebound ownership accepted: %v", err)
	}
	ownership.record.Generation.Value--
	if err := construct().RemoveMember(t.Context(), "remove", member, nil); err != nil {
		t.Fatal(err)
	}
	if journal.record.Stage != hostremoval.StageComplete || gateway.terminations != 1 || ownership.reads < 3 {
		t.Fatalf("restart: %+v calls=%d ownership reads=%d", journal.record, gateway.terminations, ownership.reads)
	}
	gateway.failure = unavailable
	if err := construct().RemoveMember(t.Context(), "remove", member, nil); err != nil {
		t.Fatalf("completed journal reread provider: %v", err)
	}
}

type removalProviderCAS struct {
	values    map[string][]byte
	revisions map[string]uint64
}

func (c *removalProviderCAS) Get(_ context.Context, key string) ([]byte, uint64, error) {
	return slices.Clone(c.values[key]), c.revisions[key], nil
}
func (c *removalProviderCAS) CompareAndSwap(_ context.Context, key string, expected uint64, value []byte) error {
	if c.revisions[key] != expected {
		return provider.OwnershipCASConflict{}
	}
	c.values[key] = slices.Clone(value)
	c.revisions[key]++
	return nil
}

type removalProviderHTTP func(*http.Request) (*http.Response, error)

func (f removalProviderHTTP) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRemovalRuntimeUsesDurableConditionalProviderTermination(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "asynchronous", true: "dropped response"}[lost], func(t *testing.T) {
			member := ocireconcile.ObservedMember{ID: "ocid1.instance.oc1.x", CompartmentID: "ocid1.compartment.oc1.x", Region: "gru", Index: 1}
			state := "RUNNING"
			deletes := 0
			host, _ := provider.OCIServiceHost(provider.OCIServiceCore, "sa-saopaulo-1")
			transportConfig, err := provider.NewOCIServiceTransportConfig(provider.OCIServiceCore, "sa-saopaulo-1", "https://"+host)
			if err != nil {
				t.Fatal(err)
			}
			transport, err := provider.NewOCIHTTPTransport(transportConfig, &http.Client{Transport: removalProviderHTTP(func(request *http.Request) (*http.Response, error) {
				if request.Method == http.MethodDelete {
					if request.Header.Get("If-Match") != "original-etag" {
						t.Fatalf("changed precondition %s", request.Header.Get("If-Match"))
					}
					deletes++
					state = "TERMINATING"
					if lost {
						return nil, io.ErrUnexpectedEOF
					}
					return &http.Response{StatusCode: 202, Header: http.Header{}, Body: http.NoBody}, nil
				}
				if request.Method != http.MethodGet || request.URL.Path != "/20160918/instances/"+member.ID {
					t.Fatalf("unexpected provider call %s %s", request.Method, request.URL.Path)
				}
				etag := "original-etag"
				if state != "RUNNING" {
					etag = "next-etag"
				}
				body := `{"id":"` + member.ID + `","compartmentId":"` + member.CompartmentID + `","lifecycleState":"` + state + `"}`
				return &http.Response{StatusCode: 200, Header: http.Header{"Etag": []string{etag}}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}, nil)
			if err != nil {
				t.Fatal(err)
			}
			providerJournal, err := provider.NewCASProviderMutationJournal(&removalProviderCAS{values: map[string][]byte{}, revisions: map[string]uint64{}})
			if err != nil {
				t.Fatal(err)
			}
			ownership := &runtimeRemovalOwnership{record: provider.ProviderOwnershipRecord{ResourceId: provider.ProviderResourceId{Value: member.ID}, CompartmentId: provider.ProviderCompartmentId{Value: member.CompartmentID}, CellId: provider.ProviderCellId{Value: "gru"}, Generation: provider.ProviderGeneration{Value: 7}, ServerIdentity: "spiffe://terrascale.tech/prod/member/original"}}
			removalJournal := &runtimeRemovalJournal{}
			construct := func(epoch uint64) *productionHostRemoval {
				adapter := &provider.OCIComputeAdapter{Core: transport, Journal: providerJournal, Ownership: ownership}
				gateway, err := ocireconcile.NewDurableOCIMemberGateway(transport, adapter, member.CompartmentID, "ocid1.image.oc1.x", provider.ProviderEpoch{Value: epoch})
				if err != nil {
					t.Fatal(err)
				}
				return &productionHostRemoval{observeFn: newProductionDurableMemberObserver(ownership, gateway), terminateFn: newProductionOCITerminator(map[string]ocireconcile.ComputeGateway{"gru": gateway}), owner: &hostremoval.Owner{Journal: removalJournal,
					Inventory: func(context.Context, hostremoval.RemovalRequest, []hostremoval.Replacement) (uint64, []hostremoval.Replacement, error) {
						return 1, nil, nil
					}, Replace: func(context.Context, hostremoval.Replacement) error { return nil }, Revalidate: func(context.Context, string, string, uint64) error { return nil }, Fence: func(context.Context, string, string, []hostremoval.Replacement) error { return nil }}}
			}
			if err := construct(1).RemoveMember(t.Context(), "remove", member, nil); err == nil {
				t.Fatal("submission reported complete")
			}
			if err := construct(2).RemoveMember(t.Context(), "remove", member, nil); !errors.Is(err, provider.ErrComputeTerminationPending) {
				t.Fatalf("restart during terminating: %v", err)
			}
			if deletes != 1 || removalJournal.record.Stage != hostremoval.StageFenced {
				t.Fatalf("pending calls=%d stage=%s", deletes, removalJournal.record.Stage)
			}
			state = "TERMINATED"
			if err := construct(2).RemoveMember(t.Context(), "remove", member, nil); err != nil {
				t.Fatal(err)
			}
			if deletes != 1 || removalJournal.record.Stage != hostremoval.StageComplete {
				t.Fatalf("terminal calls=%d stage=%s", deletes, removalJournal.record.Stage)
			}
		})
	}
}
