// Package capacitysim runs 20 regions in one process on a simulated clock and
// proves that their scalers and the home allocator share one budget without
// breaking the node bounds, the cooldowns, the partition hold or the region
// guardrails. The package has no production code: the fake pools, hosts,
// leader and record store, the demand profile and the planner's synthetic
// statuses all live in _test.go files.
//
// TestTwentyRegionsScaleUnderOneBudget runs two simulated days at the scaler
// interval. Every step it asserts that each region stays within 3..12 nodes,
// that no scale-up starts within the up cooldown and no scale-down within the
// down cooldown of the region's last change, that fleet spend never exceeds
// the cap, and that a partitioned region stops growing once its last capacity
// goes stale.
//
// TestRegionPlannerGuardrailsOverTwentyDays steps the region planner alone for
// 40 simulated days at its own interval. It asserts that the home is never
// removed, that at least MinRegions serve, that region actions are spaced by
// ActionCooldown, that a removed region is not re-added within ReaddCooldown,
// and that only one region action is open at a time.
package capacitysim
