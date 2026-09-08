package snapshotfacts

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"math"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
)

// ObserveSourceState returns unsigned evidence for the trusted retirement
// owner. The caller must retain its verified quiescence fence through shutdown;
// this read-only function cannot establish that fence or mint authority.
func ObserveSourceState(ctx context.Context, v controltransition.VerifiedPlan, connections map[string]*nats.Conn, quiescedAt time.Time) (controltransition.SourceStateReceipt, error) {
	var zero controltransition.SourceStateReceipt
	if ctx == nil || v.Check(quiescedAt) != nil || quiescedAt.After(time.Now()) {
		return zero, errors.New("snapshotfacts: source quiescence identity required")
	}
	p, err := v.Plan()
	if err != nil {
		return zero, err
	}
	type observedLease struct {
		data     []byte
		revision uint64
		epoch    int64
		key      string
	}
	before := make([]observedLease, len(p.Accounts))
	for i, a := range p.Accounts {
		key, want := "authority.regional", "gru-regional"
		floor := p.RegionalElectionFloor
		if a.Role == "global" {
			key, want = "authority.global", "global"
			floor = p.GlobalElectionFloor
		}
		data, revision, err := nodeauthority.ReadLeaderKV(ctx, connections[a.SourceName], "ORCH_LEADERS", key)
		if err != nil {
			return zero, err
		}
		var lease authority.RegionalAuthorityLeaseDocument
		if len(data) > 16<<10 || json.Unmarshal(data, &lease, json.RejectUnknownMembers(true)) != nil || lease.Validate() != nil || lease.AuthorityId != want || lease.Epoch < floor || lease.Epoch == math.MaxInt64 {
			return zero, errors.New("snapshotfacts: final accepted election floor invalid")
		}
		before[i] = observedLease{data: data, revision: revision, epoch: lease.Epoch, key: key}
	}
	streams, err := ObserveSource(ctx, v, connections, uint64(before[0].epoch))
	if err != nil {
		return zero, err
	}
	for i, a := range p.Accounts {
		data, revision, err := nodeauthority.ReadLeaderKV(ctx, connections[a.SourceName], "ORCH_LEADERS", before[i].key)
		if err != nil || revision != before[i].revision || !bytes.Equal(data, before[i].data) {
			return zero, errors.New("snapshotfacts: accepted authority changed during final observation")
		}
	}
	return controltransition.SourceStateReceipt{Version: 1, Phase: "source-quiesced", PlanSHA256: v.Digest(), NodeID: p.Source.NodeID, QuiescedAt: quiescedAt, ObservedAt: time.Now().UTC(), GlobalElectionFloor: before[0].epoch, RegionalElectionFloor: before[1].epoch, Streams: streams}, nil
}
