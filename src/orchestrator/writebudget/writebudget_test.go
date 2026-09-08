package writebudget

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/security"
)

func TestAllocationGoldenVector(t *testing.T) {
	key := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()}, D: new(big.Int).SetInt64(1)}
	key.PublicKey.X, key.PublicKey.Y = key.Curve.ScalarBaseMult(key.D.Bytes())
	signer, err := security.NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	grant := Grant{OperationID: "op-vector", OrganizationID: "org", DatabaseID: "db", HolderID: "writer-vector", RequestedUnits: 1, Regions: []string{"GRU", "SFO"}, Units: 2, PolicyEpoch: 3, ConsentEpoch: 4, WriterEpoch: 9, IssuedAt: time.Unix(1700000000, 0).UTC(), ExpiresAt: time.Unix(1700003600, 0).UTC()}
	vector, err := SignAllocation(signer, grant, "cycle", 1000, "db-placement")
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("key_id=%s spki=%x payload=%s signature=%x", signer.PublicKeyID(), spki, vector.Payload, vector.Signature)
}

func TestCanonicalAllocateAndSignVectors(t *testing.T) {
	key := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()}, D: new(big.Int).SetInt64(1)}
	key.PublicKey.X, key.PublicKey.Y = key.Curve.ScalarBaseMult(key.D.Bytes())
	signer, err := security.NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	var vectors []map[string]any
	grants := []PoolGrant{
		{SchemaVersion: 2, Kind: "regional_write_pool_refill", RefillOperationID: "refill-vector-1", PoolID: "pool-vector-1", CycleID: "cycle", RateNanoDollar: 1000, OrganizationID: "org", DatabaseID: "db", BranchID: "main", HolderID: "writer-vector-1", Region: "gru", Regions: []string{"gru", "sfo"}, Placement: "db-placement", LocalUnits: 1, AggregateUnits: 2, IncludedLocal: 1, PaidLocal: 0, IncludedAggregate: 2, PaidAggregate: 0, PoolSequence: 1, PolicyEpoch: 1, ConsentEpoch: 1, WriterEpoch: 9, IssuedAt: time.Unix(1800000000, 0).UTC(), ExpiresAt: time.Unix(1800003600, 0).UTC()},
		{SchemaVersion: 2, Kind: "regional_write_pool_refill", RefillOperationID: "refill-vector-2", PoolID: "pool-vector-2", CycleID: "cycle", RateNanoDollar: 1000, OrganizationID: "org", DatabaseID: "db", BranchID: "main", HolderID: "writer-vector-2", Region: "gru", Regions: []string{"gru", "sfo"}, Placement: "db-placement", LocalUnits: 2, AggregateUnits: 4, IncludedLocal: 2, PaidLocal: 0, IncludedAggregate: 4, PaidAggregate: 0, PoolSequence: 2, PolicyEpoch: 1, ConsentEpoch: 1, WriterEpoch: 9, IssuedAt: time.Unix(1800000000, 0).UTC(), ExpiresAt: time.Unix(1800003600, 0).UTC()},
		{SchemaVersion: 2, Kind: "regional_write_pool_refill", RefillOperationID: "refill-vector-crossing", PoolID: "pool-vector-crossing", CycleID: "cycle-cross", RateNanoDollar: 1000, OrganizationID: "org", DatabaseID: "db", BranchID: "main", HolderID: "writer-vector-crossing", Region: "gru", Regions: []string{"gru", "sfo"}, Placement: "db-placement", LocalUnits: 2, AggregateUnits: 4, IncludedLocal: 1, PaidLocal: 1, IncludedAggregate: 2, PaidAggregate: 2, PoolSequence: 3, PolicyEpoch: 1, ConsentEpoch: 1, WriterEpoch: 9, IssuedAt: time.Unix(1800000000, 0).UTC(), ExpiresAt: time.Unix(1800003600, 0).UTC()},
	}
	for _, grant := range grants {
		signed, err := SignPoolRefill(signer, grant)
		if err != nil {
			t.Fatal(err)
		}
		vectors = append(vectors, map[string]any{"localUnits": grant.LocalUnits, "aggregateUnits": grant.AggregateUnits, "includedLocalUnits": grant.IncludedLocal, "paidLocalUnits": grant.PaidLocal, "includedAggregateUnits": grant.IncludedAggregate, "paidAggregateUnits": grant.PaidAggregate, "payload": base64.StdEncoding.EncodeToString(signed.Payload), "signature": base64.StdEncoding.EncodeToString(signed.Signature)})
	}
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		spki, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
		raw, _ := json.MarshalIndent(map[string]any{"keyID": signer.PublicKeyID(), "publicSPKI": base64.StdEncoding.EncodeToString(spki), "vectors": vectors}, "", "  ")
		_ = os.WriteFile(filepath.Join("testdata", "allocation-canonical-vectors.json"), append(raw, '\n'), 0o600)
	}
}

func TestZeroAllowancePAYGAllocatesPaidUnits(t *testing.T) {
	persist := NewMemoryPersister()
	a, err := New(persist, Policy{OrganizationID: "org", CycleID: "payg", PolicyEpoch: 1, ConsentEpoch: 1, WriterEpoch: 1, WriterEpochs: map[string]uint64{"writer-payg": 4}, IncludedAllowanceUnits: 0, PaidExcessEnabled: true, RateNanoDollar: 1000})
	if err != nil {
		t.Fatal(err)
	}
	r := request("payg", "db", "main", 1, time.Now().Add(time.Hour))
	r.PolicyEpoch, r.ConsentEpoch = 1, 1
	r.HolderID = "writer-payg"
	grant, err := a.Allocate(t.Context(), r)
	if err != nil || grant.IncludedUnits != 0 || grant.PaidUnits != 2 || grant.CostNanoDollar != 2000 {
		t.Fatalf("grant=%+v err=%v", grant, err)
	}
}

func TestZeroAllowanceWithoutPaidConsentDeniesWrites(t *testing.T) {
	a, err := New(NewMemoryPersister(), Policy{OrganizationID: "org", CycleID: "free", PolicyEpoch: 1, ConsentEpoch: 1, WriterEpoch: 1, WriterEpochs: map[string]uint64{"writer-free": 1}, IncludedAllowanceUnits: 0, PaidExcessEnabled: false, RateNanoDollar: 1000})
	if err != nil {
		t.Fatal(err)
	}
	r := request("free", "db", "main", 1, time.Now().Add(time.Hour))
	r.PolicyEpoch, r.ConsentEpoch, r.HolderID = 1, 1, "writer-free"
	if _, err := a.Allocate(t.Context(), r); !errors.Is(err, ErrExhausted) {
		t.Fatalf("allocation error=%v", err)
	}
}

func testAuthority(t *testing.T) (*Authority, *MemoryPersister) {
	t.Helper()
	persist := NewMemoryPersister()
	epochs := map[string]uint64{"writer-one": 1, "writer-two": 1, "writer-same": 1, "writer-revoke": 1, "writer-split-a": 1, "writer-split-b": 1, "writer-combined": 1}
	for i := range 20 {
		epochs[fmt.Sprintf("writer-concurrent-%d", i)] = 1
	}
	organizationCap := int64(100000)
	databaseCap := int64(80000)
	authority, err := New(persist, Policy{OrganizationID: "org", CycleID: "cycle", PolicyEpoch: 3, ConsentEpoch: 4, WriterEpoch: 1, WriterEpochs: epochs, IncludedAllowanceUnits: 10, PaidExcessEnabled: false, RateNanoDollar: 1000, OrganizationSpendCap: &organizationCap, DatabaseSpendCaps: map[string]*int64{"db": &databaseCap}})
	if err != nil {
		t.Fatal(err)
	}
	return authority, persist
}

func request(id, db, branch string, units int64, expiry time.Time) Request {
	return Request{OperationID: id, OrganizationID: "org", DatabaseID: db, BranchID: branch, HolderID: "writer-" + id, Regions: []string{"gru", "sfo"}, Units: units, PolicyEpoch: 3, ConsentEpoch: 4, WriterEpoch: 1, ExpiresAt: expiry}
}

func TestAllocateMultipliesRegionsOnceAndBranchesShareCaps(t *testing.T) {
	authority, _ := testAuthority(t)
	expires := time.Now().Add(time.Hour)
	grant, err := authority.Allocate(t.Context(), request("one", "db", "main", 3, expires))
	if err != nil {
		t.Fatal(err)
	}
	if grant.Units != 6 || grant.IncludedUnits != 6 || grant.CostNanoDollar != 0 {
		t.Fatalf("grant = %+v", grant)
	}
	if _, err := authority.Allocate(t.Context(), request("two", "db", "branch", 2, expires)); err != nil {
		t.Fatal(err)
	}
}

func TestAllocateRetryReconcilesExactOperation(t *testing.T) {
	authority, _ := testAuthority(t)
	r := request("same", "db", "main", 1, time.Now().Add(time.Hour))
	first, err := authority.Allocate(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := authority.Allocate(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(retry, first) {
		t.Fatalf("retry = %+v, first = %+v", retry, first)
	}
	changed := r
	changed.Units = 2
	if _, err := authority.Allocate(t.Context(), changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed retry error = %v", err)
	}
}

func TestRevocationRemainsPendingUntilFence(t *testing.T) {
	authority, _ := testAuthority(t)
	grant, err := authority.Allocate(t.Context(), request("revoke", "db", "main", 1, time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Revoke(t.Context(), grant.OperationID); !errors.Is(err, ErrPending) {
		t.Fatalf("revoke error = %v", err)
	}
	pending, found, err := authority.Lookup(t.Context(), grant.OperationID)
	if err != nil || !found || !pending.Revoked || pending.Fenced {
		t.Fatalf("pending = %+v found=%v err=%v", pending, found, err)
	}
	if err := authority.Fence(t.Context(), grant.OperationID); err != nil {
		t.Fatal(err)
	}
	if err := authority.Revoke(t.Context(), grant.OperationID); err != nil {
		t.Fatal(err)
	}
}

func TestEpochAndExpiryFenceRequest(t *testing.T) {
	authority, _ := testAuthority(t)
	r := request("bad", "db", "main", 1, time.Now().Add(time.Hour))
	r.PolicyEpoch++
	if _, err := authority.Allocate(t.Context(), r); !errors.Is(err, ErrInvalid) {
		t.Fatalf("epoch error = %v", err)
	}
	r = request("expired", "db", "main", 1, time.Now().Add(-time.Second))
	if _, err := authority.Allocate(t.Context(), r); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expiry error = %v", err)
	}
}

func TestSplitAndCombinedReservationsHaveSameIntegerCharge(t *testing.T) {
	combined, _ := testAuthority(t)
	split, _ := testAuthority(t)
	expires := time.Now().Add(time.Hour)
	grant, err := combined.Allocate(t.Context(), request("combined", "db", "main", 4, expires))
	if err != nil {
		t.Fatal(err)
	}
	first, err := split.Allocate(t.Context(), request("split-a", "db", "main", 1, expires))
	if err != nil {
		t.Fatal(err)
	}
	second, err := split.Allocate(t.Context(), request("split-b", "db", "main", 3, expires))
	if err != nil {
		t.Fatal(err)
	}
	if grant.Units != first.Units+second.Units || grant.CostNanoDollar != first.CostNanoDollar+second.CostNanoDollar {
		t.Fatalf("combined=%+v split=%+v,%+v", grant, first, second)
	}
}

func TestConcurrentReservationsCannotExceedAllowance(t *testing.T) {
	authority, _ := testAuthority(t)
	// Two regions and five logical units leave ten chargeable units available.
	var wg sync.WaitGroup
	results := make(chan error, 20)
	for i := range 20 {
		id := fmt.Sprintf("concurrent-%d", i)
		wg.Go(func() {
			_, err := authority.Allocate(t.Context(), request(id, "db", "main", 1, time.Now().Add(time.Hour)))
			results <- err
		})
	}
	wg.Wait()
	close(results)
	var success, exhausted int
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrExhausted) {
			exhausted++
		} else {
			t.Fatalf("reservation error = %v", err)
		}
	}
	if success != 5 || exhausted != 15 { // included allowance is ten chargeable units
		t.Fatalf("success=%d exhausted=%d", success, exhausted)
	}
}
