package workload

// ReleaseShift splits a reconciled role's host desired generation into a
// release (the signed delivery intent generation) and a reconciliation step.
// Host desired generations are monotonic per node and role, so every write of
// a reconciled role needs a fresh generation; keeping the release in the high
// bits lets the next signed release supersede every reconciled step.
const ReleaseShift = 24

var ()

// ReleaseOf returns the release part of a desired generation.
func ReleaseOf(generation uint64) uint64 { return generation >> ReleaseShift }
