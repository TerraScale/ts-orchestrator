package placement

import "testing"

// residencyTestCatalog is the launch catalog: GRU is the br Region, FRA the
// eu Region, SFO the us Region, each with the two-host floor.
func residencyTestCatalog() *RegionCatalog {
	return NewRegionCatalog([]*RegionCatalogEntry{
		{Region: RegionCodeGru, Available: true, Permitted: true, ResidencyAllowed: true, Residency: "br", MemberHosts: 2},
		{Region: RegionCodeSfo, Available: true, Permitted: true, ResidencyAllowed: true, Residency: "us", MemberHosts: 2},
		{Region: RegionCodeFra, Available: true, Permitted: true, ResidencyAllowed: true, Residency: "eu", MemberHosts: 2},
	})
}

// residencyTestRequest builds an admissible intent for exactly the active
// Regions: one logical partition with two RF=2 seats per Region in
// independent failure domains.
func residencyTestRequest(lock *PlacementLock, active ...RegionCode) *DatabasePlacementRequest {
	partition := PartitionId{Value: "residency-partition"}
	placements := make([]*PartitionRegionPlacement, 0, len(active))
	for _, region := range active {
		seats := []*ActiveMemberSeat{
			{Member: MemberId{Value: "member-" + region.Value() + "-1"}, Region: region, Partition: partition,
				FailureDomain: FailureDomainId{Value: "AD-1"}, IsActive: true},
			{Member: MemberId{Value: "member-" + region.Value() + "-2"}, Region: region, Partition: partition,
				FailureDomain: FailureDomainId{Value: "AD-2"}, IsActive: true},
		}
		placement := NewPartitionRegionPlacement(region, seats)
		placements = append(placements, &placement)
	}
	logical := NewLogicalPartitionPlacement(partition, placements)
	return NewDatabasePlacementRequest(active, []*LogicalPartitionPlacement{&logical}, nil, lock)
}

// residencyTestHasError reports whether the decision carries one error code.
func residencyTestHasError(decision *DatabasePlacementDecision, code DatabasePlacementErrorCode) bool {
	for _, err := range decision.Errors {
		if err.Code == code {
			return true
		}
	}
	return false
}

func TestEvaluatorHonoursNamedResidencyLocks(t *testing.T) {
	catalog := residencyTestCatalog()

	euOnly, err := NewEUOnlyPlacementLock(1)
	if err != nil {
		t.Fatal(err)
	}
	decision := DatabasePlacementEvaluator.Evaluate(residencyTestRequest(euOnly, RegionCodeFra), catalog)
	if !decision.Accepted() {
		t.Fatalf("eu-only intent in FRA refused: %+v", decision.Errors)
	}
	if decision.EffectiveLock == nil || decision.EffectiveLock.Kind != PlacementLockKindEUOnly ||
		len(decision.EffectiveLock.Regions) != 1 || decision.EffectiveLock.Regions[0] != RegionCodeFra {
		t.Fatalf("eu-only effective lock = %#v", decision.EffectiveLock)
	}

	brOnly, err := NewBROnlyPlacementLock(1)
	if err != nil {
		t.Fatal(err)
	}
	decision = DatabasePlacementEvaluator.Evaluate(residencyTestRequest(brOnly, RegionCodeGru), catalog)
	if !decision.Accepted() {
		t.Fatalf("br-only intent in GRU refused: %+v", decision.Errors)
	}

	// A named lock refuses every Region outside its jurisdiction, even when
	// the Region is otherwise healthy and permitted.
	decision = DatabasePlacementEvaluator.Evaluate(residencyTestRequest(euOnly, RegionCodeGru), catalog)
	if decision.Accepted() || !residencyTestHasError(decision, DatabasePlacementErrorCodePlacementLockRegionOutside) {
		t.Fatalf("eu-only intent in GRU accepted: %+v", decision.Errors)
	}
	decision = DatabasePlacementEvaluator.Evaluate(residencyTestRequest(brOnly, RegionCodeSfo), catalog)
	if decision.Accepted() || !residencyTestHasError(decision, DatabasePlacementErrorCodePlacementLockRegionOutside) {
		t.Fatalf("br-only intent in SFO accepted: %+v", decision.Errors)
	}
}

func TestEvaluatorHonoursExplicitRegionListLock(t *testing.T) {
	catalog := residencyTestCatalog()
	lock, err := NewExplicitPlacementLock([]RegionCode{RegionCodeGru, RegionCodeSfo}, 1)
	if err != nil {
		t.Fatal(err)
	}
	decision := DatabasePlacementEvaluator.Evaluate(residencyTestRequest(lock, RegionCodeGru), catalog)
	if !decision.Accepted() {
		t.Fatalf("explicit intent in a listed Region refused: %+v", decision.Errors)
	}
	decision = DatabasePlacementEvaluator.Evaluate(residencyTestRequest(lock, RegionCodeFra), catalog)
	if decision.Accepted() || !residencyTestHasError(decision, DatabasePlacementErrorCodePlacementLockRegionOutside) {
		t.Fatalf("explicit intent outside the listed Regions accepted: %+v", decision.Errors)
	}
}

func TestEvaluatorRefusesLockWidening(t *testing.T) {
	catalog := residencyTestCatalog()
	prior, err := NewExplicitPlacementLock([]RegionCode{RegionCodeGru}, 5)
	if err != nil {
		t.Fatal(err)
	}

	// Adding a Region to an explicit lock is refused even with a newer
	// generation.
	widened, err := NewExplicitPlacementLock([]RegionCode{RegionCodeGru, RegionCodeSfo}, 6)
	if err != nil {
		t.Fatal(err)
	}
	request := residencyTestRequest(widened, RegionCodeGru, RegionCodeSfo)
	request.PreviousLock = prior
	decision := DatabasePlacementEvaluator.Evaluate(request, catalog)
	if decision.Accepted() || !residencyTestHasError(decision, DatabasePlacementErrorCodePlacementLockWidened) {
		t.Fatalf("widened lock accepted: %+v", decision.Errors)
	}

	// Narrowing with a strictly newer generation stays admissible.
	narrowed, err := NewExplicitPlacementLock([]RegionCode{RegionCodeGru}, 6)
	if err != nil {
		t.Fatal(err)
	}
	request = residencyTestRequest(narrowed, RegionCodeGru)
	request.PreviousLock, err = NewExplicitPlacementLock([]RegionCode{RegionCodeGru, RegionCodeSfo}, 5)
	if err != nil {
		t.Fatal(err)
	}
	decision = DatabasePlacementEvaluator.Evaluate(request, catalog)
	if !decision.Accepted() {
		t.Fatalf("narrowed lock refused: %+v", decision.Errors)
	}
}

func TestEvaluatorRefusesNamedLockCatalogWidening(t *testing.T) {
	// A eu-only lock resolved when only FRA existed must not silently grow
	// when the catalog later registers another eu Region: the named lock's
	// resolved set is as immutable as an explicit list.
	euOnly, err := NewEUOnlyPlacementLock(1)
	if err != nil {
		t.Fatal(err)
	}
	prior, err := ResolvePlacementLock(euOnly, residencyTestCatalog())
	if err != nil {
		t.Fatal(err)
	}

	grown := residencyTestCatalog()
	ams := mustRegionCode("AMS")
	grown.Regions = append(grown.Regions, &RegionCatalogEntry{
		Region: ams, Available: true, Permitted: true,
		ResidencyAllowed: true, Residency: "eu", MemberHosts: 2,
	})
	request := residencyTestRequest(euOnly, RegionCodeFra, ams)
	request.PreviousLock = prior
	decision := DatabasePlacementEvaluator.Evaluate(request, grown)
	if decision.Accepted() || !residencyTestHasError(decision, DatabasePlacementErrorCodePlacementLockWidened) {
		t.Fatalf("catalog-grown eu-only lock accepted: %+v", decision.Errors)
	}
}

func TestEvaluatorRefusesRegionBelowMemberHostFloor(t *testing.T) {
	catalog := residencyTestCatalog()
	for index, entry := range catalog.Regions {
		if entry.Region == RegionCodeFra {
			catalog.Regions[index].MemberHosts = 1
		}
	}
	euOnly, err := NewEUOnlyPlacementLock(1)
	if err != nil {
		t.Fatal(err)
	}
	decision := DatabasePlacementEvaluator.Evaluate(residencyTestRequest(euOnly, RegionCodeFra), catalog)
	if decision.Accepted() || !residencyTestHasError(decision, DatabasePlacementErrorCodeRegionMemberHostFloor) {
		t.Fatalf("one-host Region accepted: %+v", decision.Errors)
	}
}

func TestEvaluatorRefusesBackupOutsideLock(t *testing.T) {
	catalog := residencyTestCatalog()
	euOnly, err := NewEUOnlyPlacementLock(1)
	if err != nil {
		t.Fatal(err)
	}
	request := residencyTestRequest(euOnly, RegionCodeFra)
	request.Backup = &BackupPlacement{
		Backup: BackupId{Value: "residency-backup"}, Region: RegionCodeSfo,
		IsReadOnly: true, IsImmutable: true, PromotionPolicy: BackupPromotionPolicyNeverPromote,
	}
	decision := DatabasePlacementEvaluator.Evaluate(request, catalog)
	if decision.Accepted() || !residencyTestHasError(decision, DatabasePlacementErrorCodeBackupOutsidePlacementLock) {
		t.Fatalf("backup outside the eu-only lock accepted: %+v", decision.Errors)
	}
}
