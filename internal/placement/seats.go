package placement

// MinSeatsPerRegion is the TerraBase quorum floor: one permanent and at least
// one elastic member on distinct failure domains in every active region.
const MinSeatsPerRegion = 2

// SeatsPerRegion is the member count the current schema admits. The signed
// canonical roster, managed material and the single-peer replication runtime
// manifest still bind exactly two members per region, so a larger count
// requires a new intent schema before it can be used; RegionSeats already
// produces the generalized layout.
const SeatsPerRegion = MinSeatsPerRegion
