package budget

import (
	"cmp"
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/globalcontrol"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// This exercises persisted commitments, not spending admission: no fixture can
// manufacture the complete accounting evidence the production producer lacks.
func TestReservationLedgerSurvivesPeriodicWritesThroughHomeCAS(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	writer, concurrent, epoch := reservationStoreHome(t, ctx)
	now := time.Now().UTC()
	monthly := Budget{Schema: Schema, ID: entityid.New(), MonthlyCapCents: 1000, Currency: "USD", SetBy: "integration", SetAt: now}
	if err := WriteBudget(ctx, writer, epoch, monthly); err != nil {
		t.Fatal(err)
	}
	regions := []Region{
		{Cell: "gru", Nodes: 1, Want: 2, Pressure: .9, NodeMonthlyCents: 300, ProjectedCents: 100, Currency: "USD", At: now},
		{Cell: "sfo", Nodes: 1, Want: 2, Pressure: .5, NodeMonthlyCents: 300, ProjectedCents: 100, Currency: "USD", At: now},
	}
	allocated := Allocate(&monthly, regions, nil, now)
	if err := WriteCapacity(ctx, writer, epoch, allocated); err != nil {
		t.Fatal(err)
	}
	persisted, found, err := ReadCapacity(ctx, &writer.Reader)
	if err != nil || !found || persisted.ProjectedCents != 800 || persisted.Headroom() != 200 || persisted.State != StateWarn {
		t.Fatalf("new grants must count in persisted headroom: %+v, found=%v, err=%v", persisted, found, err)
	}
	seed := Reservation{OperationID: entityid.New(), RecipeSHA256: strings.Repeat("a", 64), Cell: "gru", CompartmentID: "ocid1.compartment.oc1..integration",
		Shape: "VM.Standard.A1.Flex", OCPUs: 2, MemoryGB: 4, BootGB: 50, MonthlyCents: 300, BudgetID: monthly.ID,
		InfrastructureBudgetID: entityid.New(), GrantSHA256: strings.Repeat("b", 64), ScopeSHA256: strings.Repeat("c", 64),
		IssuedAt: now.Add(-time.Hour), LaunchExpiresAt: now.Add(-30 * time.Minute)}
	appendCommitment := func(reservation Reservation) error {
		for range 32 {
			current, found, err := ReadCapacity(ctx, &concurrent.Reader)
			if err != nil || !found {
				return errors.Join(err, errors.New("capacity ledger unavailable"))
			}
			expected, err := current.Encode()
			if err != nil {
				return err
			}
			current.Reservations = append(current.Reservations, reservation)
			slices.SortFunc(current.Reservations, func(a, b Reservation) int { return cmp.Compare(a.OperationID, b.OperationID) })
			payload, err := current.Encode()
			if err != nil {
				return err
			}
			_, err = concurrent.PutDocument(ctx, epoch, globalcontrol.KindCapacity, protocol.GlobalScope, payload, func(stored []byte) error {
				if !sameCapacity(stored, expected) {
					return globalcontrol.ErrConflict
				}
				return nil
			})
			if errors.Is(err, globalcontrol.ErrConflict) {
				continue
			}
			return err
		}
		return globalcontrol.ErrConflict
	}
	if err := appendCommitment(seed); err != nil {
		t.Fatal(err)
	}
	// The caller's stale allocation predates the stored, already-expired receipt.
	if err := WriteCapacity(ctx, writer, epoch, allocated); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	second := seed
	second.OperationID = entityid.New()
	go func() {
		<-start
		results <- appendCommitment(second)
	}()
	go func() {
		<-start
		for range 16 {
			if err := WriteCapacity(ctx, writer, epoch, allocated); err != nil {
				results <- err
				return
			}
		}
		results <- nil
	}()
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	persisted, found, err = ReadCapacity(ctx, &writer.Reader)
	if err != nil || !found || len(persisted.Reservations) != 2 {
		t.Fatalf("concurrent periodic write erased commitments: %+v, found=%v, err=%v", persisted, found, err)
	}
	for _, candidate := range []Capacity{
		Allocate(nil, regions, &persisted, now.Add(2*time.Hour)),
		Allocate(&monthly, regions, &persisted, now.Add(StatusMaxAge+time.Minute)),
	} {
		if err := WriteCapacity(ctx, writer, epoch, candidate); err != nil {
			t.Fatal(err)
		}
		stored, found, err := ReadCapacity(ctx, &writer.Reader)
		if err != nil || !found || len(stored.Reservations) != 2 {
			t.Fatalf("unknown budget/spend or expired launch released commitments: %+v, found=%v, err=%v", stored, found, err)
		}
		for _, receipt := range stored.Reservations {
			if receipt.MonthlyCents != 300 || !receipt.RetiredAt.IsZero() || len(receipt.ResourceIDs) != 0 {
				t.Fatalf("unknown outcome was changed or retired: %+v", receipt)
			}
		}
	}
}

func reservationStoreHome(t *testing.T, ctx context.Context) (*globalcontrol.Writer, *globalcontrol.Writer, uint64) {
	t.Helper()
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: filepath.Join(t.TempDir(), "jetstream")})
	if err != nil {
		t.Fatal(err)
	}
	go broker.Start()
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	conn, err := nats.Connect(broker.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := authority.Start(ctx, js, authority.Config{DeploymentID: entityid.New(), Scope: protocol.GlobalScope, CandidateID: entityid.New(), Replicas: 1,
		LeaseDuration: 5 * time.Second, RenewInterval: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	for !runtime.Current().CanMutate() {
		select {
		case <-ctx.Done():
			t.Fatal("global authority never became ready")
		case <-time.After(20 * time.Millisecond):
		}
	}
	writer, err := globalcontrol.OpenHome(ctx, js, "gru", nil, 1, runtime)
	if err != nil {
		t.Fatal(err)
	}
	concurrent, err := globalcontrol.OpenHome(ctx, js, "gru", nil, 1, runtime)
	if err != nil {
		t.Fatal(err)
	}
	return writer, concurrent, runtime.Current().Epoch
}
