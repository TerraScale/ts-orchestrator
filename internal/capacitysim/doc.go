// Package capacitysim runs 20 regions in one process on a simulated clock and
// proves that their scalers and the home allocator share one budget without
// breaking the node bounds, the cooldowns, the partition hold or the spend cap.
// The package has no production code: the fake pools, hosts, leader and record
// store, the demand profile and the suggester's synthetic statuses all live in
// _test.go files.
//
// TestTwentyRegionsScaleUnderOneBudget runs two simulated days at the scaler
// interval. Every step it asserts that each region stays within 3..12 nodes,
// that no scale-up starts within the up cooldown and no scale-down within the
// down cooldown of the region's last change, that fleet spend never exceeds
// the cap, and that a partitioned region stops growing once its last capacity
// goes stale.
//
// TestRegionSuggestionsOverFortyDays steps the region suggester alone for 40
// simulated days at its own interval. Nothing acts on its suggestions. It
// asserts that the home is never suggested for removal, that a removal is
// suggested only for a region idle for IdleFor, and that every add names a
// region and its monthly cost.
package capacitysim
