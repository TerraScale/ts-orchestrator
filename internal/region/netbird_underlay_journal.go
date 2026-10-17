package region

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
)

var ErrNetBirdUnderlayPending = errors.New("NetBird private underlay has an unresolved original dispatch")

var netBirdUnderlaySteps = []string{"manager_gateway", "writer_gateway", "connect", "manager_route", "writer_route", "writer_security"}

type NetBirdUnderlayRecord = bootstrap.NetBirdUnderlayRecord
type NetBirdUnderlayEndpoint = bootstrap.NetBirdUnderlayEndpoint
type NetBirdUnderlayRequest = bootstrap.NetBirdUnderlayRequest

func netBirdUnderlayNativeID(kind, id string) bool {
	return len(id) <= 512 && strings.HasPrefix(id, "ocid1."+kind+".oc1.sa-saopaulo-1.") && len(strings.TrimPrefix(id, "ocid1."+kind+".oc1.sa-saopaulo-1.")) > 0
}

func netBirdUnderlayEqual(first, second any) bool {
	a, err := json.Marshal(first, json.Deterministic(true))
	if err != nil {
		return false
	}
	b, err := json.Marshal(second, json.Deterministic(true))
	return err == nil && bytes.Equal(a, b)
}

func retainNetBirdUnderlay(previous, next *NetBirdUnderlayRecord) error {
	if previous == nil {
		return nil
	}
	if next == nil {
		return errors.New("NetBird underlay original journal cannot be removed")
	}
	a, b := *previous, *next
	a.Requests, b.Requests = nil, nil
	if !netBirdUnderlayEqual(a, b) {
		return errors.New("NetBird underlay original purpose, native endpoints or cap cannot change")
	}
	for key, old := range previous.Requests {
		current, ok := next.Requests[key]
		if !ok {
			return errors.New("NetBird underlay possibly-sent request cannot be removed")
		}
		oldOutcome, currentOutcome := old, current
		old.RespondedAt, current.RespondedAt = time.Time{}, time.Time{}
		old.VerifiedAt, current.VerifiedAt = time.Time{}, time.Time{}
		old.ResponseID, current.ResponseID = "", ""
		if !netBirdUnderlayEqual(old, current) || !oldOutcome.RespondedAt.IsZero() && (oldOutcome.RespondedAt != currentOutcome.RespondedAt || oldOutcome.ResponseID != currentOutcome.ResponseID) ||
			!oldOutcome.VerifiedAt.IsZero() && oldOutcome.VerifiedAt != currentOutcome.VerifiedAt {
			return errors.New("NetBird underlay original dispatch or accepted outcome cannot change")
		}
	}
	return nil
}
