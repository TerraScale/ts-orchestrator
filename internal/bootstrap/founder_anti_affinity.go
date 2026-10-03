package bootstrap

import (
	"errors"
	"fmt"
	"strings"
)

// ErrControllerAntiAffinity reports controller slots placed in one failure
// domain, where a single fault-domain outage would remove a broker quorum.
var ErrControllerAntiAffinity = errors.New("controller slots must be in distinct OCI fault domains")

// ControllerPlacement is an OCI availability and fault domain pair.
type ControllerPlacement struct {
	AvailabilityDomain string
	FaultDomain        string
}

// key normalizes the tenancy-prefixed and bare AD spellings ("Abcd:SA-
// SAOPAULO-1-AD-1" and "SA-SAOPAULO-1-AD-1") that IMDS and signed plans use.
func (placement ControllerPlacement) key() (string, bool) {
	ad := strings.ToUpper(strings.TrimSpace(placement.AvailabilityDomain))
	if index := strings.LastIndexByte(ad, ':'); index >= 0 {
		ad = ad[index+1:]
	}
	fd := strings.ToUpper(strings.TrimSpace(placement.FaultDomain))
	return ad + "/" + fd, ad != "" && fd != ""
}

// CheckControllerAntiAffinity requires the seed and every planned peer to be
// in a distinct (availability domain, fault domain) pair. Fault domains are
// scoped to an availability domain, so peers in different ADs may reuse a
// fault-domain name. It is a launch-time check: an already founded slot is
// never relaunched because of it.
func CheckControllerAntiAffinity(seed ControllerPlacement, peers []FounderPeerRow) error {
	key, ok := seed.key()
	if !ok {
		return fmt.Errorf("%w: seed placement is unknown", ErrControllerAntiAffinity)
	}
	owner := map[string]string{key: "seed"}
	for _, peer := range peers {
		key, ok := ControllerPlacement{AvailabilityDomain: peer.AvailabilityDomain, FaultDomain: peer.FaultDomain}.key()
		if !ok {
			return fmt.Errorf("%w: peer %q placement is incomplete", ErrControllerAntiAffinity, peer.Slot)
		}
		if other, exists := owner[key]; exists {
			return fmt.Errorf("%w: peer %q shares %s with %s", ErrControllerAntiAffinity, peer.Slot, key, other)
		}
		owner[key] = fmt.Sprintf("peer %q", peer.Slot)
	}
	return nil
}
