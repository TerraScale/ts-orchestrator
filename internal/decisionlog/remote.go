package decisionlog

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlink"
)

const (
	// QueryLeaf is the observability subject leaf a region answers
	// decision queries on: ts.orch.v1.<region>.obs.decisions.
	QueryLeaf = "decisions"
	// wireVersion is the request/reply version of remote queries.
	wireVersion          = 1
	maxQueryRequestBytes = 8 << 10
	queryAnswerTimeout   = 3 * time.Second
)

type remoteRequest struct {
	Version int    `json:"version"`
	Query   Query  `json:"query,omitzero"`
	ChainID string `json:"chain_id,omitempty"`
}

type remoteReply struct {
	Version int     `json:"version"`
	Region  string  `json:"region"`
	Result  *Result `json:"result,omitempty"`
	Chain   *Chain  `json:"chain,omitempty"`
	// Error is a fixed class: not_found, invalid or unavailable.
	Error string `json:"error,omitempty"`
}

// ServeQueries answers decision queries for cell from source until ctx ends.
// Every controller of the region answers; a requester takes the first reply.
// Replies are bounded to the connection's payload limit by dropping the
// oldest decisions and marking the result truncated.
func ServeQueries(ctx context.Context, conn *nats.Conn, cell string, source Source) (*nats.Subscription, error) {
	if conn == nil || source == nil {
		return nil, errors.New("decision query responder requires a connection and a source")
	}
	subject, err := protocol.ObservabilitySubject(cell, QueryLeaf)
	if err != nil {
		return nil, err
	}
	region := strings.ToLower(cell)
	// A queue group sends each query to one controller instead of all.
	subscription, err := conn.QueueSubscribe(subject, "decisionlog", func(message *nats.Msg) {
		if message.Reply == "" || len(message.Data) > maxQueryRequestBytes {
			return
		}
		reply := answer(ctx, region, source, message.Data)
		data, err := encodeReply(reply, conn.MaxPayload())
		if err != nil {
			return
		}
		_ = message.Respond(data)
	})
	if err != nil {
		return nil, err
	}
	context.AfterFunc(ctx, func() { _ = subscription.Unsubscribe() })
	return subscription, nil
}

func answer(ctx context.Context, region string, source Source, data []byte) remoteReply {
	reply := remoteReply{Version: wireVersion, Region: region}
	var request remoteRequest
	if err := json.Unmarshal(data, &request); err != nil || request.Version != wireVersion {
		reply.Error = "invalid"
		return reply
	}
	answerCtx, cancel := context.WithTimeout(ctx, queryAnswerTimeout)
	defer cancel()
	if request.ChainID != "" {
		chain, err := source.Chain(answerCtx, request.ChainID)
		switch {
		case errors.Is(err, ErrNotFound):
			reply.Error = "not_found"
		case err != nil:
			reply.Error = "unavailable"
		default:
			reply.Chain = &chain
		}
		return reply
	}
	// A remote region answers only for itself.
	request.Query.Regions = []string{region}
	result, err := source.Query(answerCtx, request.Query)
	if err != nil {
		reply.Error = "unavailable"
		return reply
	}
	reply.Result = &result
	return reply
}

// encodeReply drops the oldest decisions until the reply fits limit bytes.
func encodeReply(reply remoteReply, limit int64) ([]byte, error) {
	for {
		data, err := json.Marshal(reply)
		if err != nil {
			return nil, err
		}
		if int64(len(data)) <= limit {
			return data, nil
		}
		switch {
		case reply.Result != nil && len(reply.Result.Decisions) > 0:
			keep := len(reply.Result.Decisions) / 2
			reply.Result.Decisions = reply.Result.Decisions[:keep]
			reply.Result.Truncated = true
		case reply.Chain != nil && len(reply.Chain.Decisions) > 1:
			reply.Chain.Decisions = reply.Chain.Decisions[len(reply.Chain.Decisions)/2:]
		default:
			return nil, errors.New("decision reply does not fit the payload limit")
		}
	}
}

// Federation answers queries across every configured region: the local
// region from Local and the others over regionlink request/reply. It
// implements Source; a region that cannot answer is reported in
// Result.Regions instead of failing the query.
type Federation struct {
	Local Source
	Links regionlink.Requester
}

// Query merges per-region results newest first.
func (federation Federation) Query(ctx context.Context, query Query) (Result, error) {
	query = query.Normalized()
	regions := federation.regions(query.Regions)
	results := make([]Result, len(regions))
	statuses := make([]RegionStatus, len(regions))
	var group sync.WaitGroup
	for index, region := range regions {
		group.Go(func() {
			regional := query
			if region != "" {
				regional.Regions = []string{region}
			}
			result, status := federation.queryRegion(ctx, region, regional)
			results[index], statuses[index] = result, status
		})
	}
	group.Wait()
	merged := Result{Regions: statuses}
	for _, result := range results {
		merged.Decisions = append(merged.Decisions, result.Decisions...)
		merged.Truncated = merged.Truncated || result.Truncated
		merged.Partial = merged.Partial || result.Partial
	}
	for _, status := range statuses {
		// A configured region that is not linked was not searched either.
		if status.State != RegionOK {
			merged.Partial = true
		}
	}
	SortNewestFirst(merged.Decisions)
	if len(merged.Decisions) > query.Limit {
		merged.Decisions = merged.Decisions[:query.Limit]
		merged.Truncated = true
	}
	return merged, nil
}

func (federation Federation) regions(filter []string) []string {
	var all []string
	local := ""
	if federation.Links != nil {
		all = federation.Links.Regions()
		local = federation.Links.Local()
	}
	if len(all) == 0 && federation.Local != nil {
		all = []string{local}
	}
	if len(filter) == 0 {
		return all
	}
	return slices.DeleteFunc(all, func(region string) bool { return !slices.Contains(filter, region) })
}

func (federation Federation) queryRegion(ctx context.Context, region string, query Query) (Result, RegionStatus) {
	status := RegionStatus{Region: region}
	if federation.Local != nil && (federation.Links == nil || region == federation.Links.Local()) {
		result, err := federation.Local.Query(ctx, query)
		if err != nil {
			status.State, status.Detail = RegionError, "local journal unavailable"
			return Result{}, status
		}
		status.State, status.Count = RegionOK, len(result.Decisions)
		return result, status
	}
	reply, err := federation.request(ctx, region, remoteRequest{Version: wireVersion, Query: query})
	if err != nil {
		status.State, status.Detail = classify(err)
		return Result{}, status
	}
	if reply.Result == nil {
		status.State, status.Detail = RegionError, "region returned no result"
		return Result{}, status
	}
	result := *reply.Result
	// Never trust a remote region to answer for another one.
	result.Decisions = slices.DeleteFunc(result.Decisions, func(decision Decision) bool {
		return decision.Region != region
	})
	status.State, status.Count = RegionOK, len(result.Decisions)
	return result, status
}

// Chain looks the chain up locally first, then in every linked region.
func (federation Federation) Chain(ctx context.Context, id string) (Chain, error) {
	if federation.Local != nil {
		chain, err := federation.Local.Chain(ctx, id)
		if err == nil {
			return chain, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return Chain{}, err
		}
	}
	if federation.Links == nil {
		return Chain{}, ErrNotFound
	}
	// Keep searching past a region that cannot answer, but do not turn its
	// failure into a negative answer: ErrNotFound only when every searched
	// region answered that it has no such decision.
	var unavailable error
	for _, region := range federation.Links.Regions() {
		if region == federation.Links.Local() || !federation.Links.Linked(region) {
			continue
		}
		reply, err := federation.request(ctx, region, remoteRequest{Version: wireVersion, ChainID: id})
		switch {
		case err == nil && reply.Chain != nil:
			return *reply.Chain, nil
		case err != nil && !errors.Is(err, ErrNotFound):
			unavailable = ErrUnavailable
		}
	}
	if unavailable != nil {
		return Chain{}, unavailable
	}
	return Chain{}, ErrNotFound
}

func (federation Federation) request(ctx context.Context, region string, request remoteRequest) (remoteReply, error) {
	if federation.Links == nil {
		return remoteReply{}, regionlink.ErrNotLinked
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return remoteReply{}, err
	}
	data, err := federation.Links.Request(ctx, region, QueryLeaf, payload)
	if err != nil {
		return remoteReply{}, err
	}
	var reply remoteReply
	if err := json.Unmarshal(data, &reply); err != nil || reply.Version != wireVersion {
		return remoteReply{}, errors.New("invalid decision reply")
	}
	if reply.Error != "" {
		if reply.Error == "not_found" {
			return remoteReply{}, ErrNotFound
		}
		return remoteReply{}, errors.New("region could not answer")
	}
	return reply, nil
}

func classify(err error) (state, detail string) {
	switch {
	case errors.Is(err, regionlink.ErrNotLinked):
		return RegionNotLinked, "no cross-region link yet"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, nats.ErrTimeout), errors.Is(err, nats.ErrNoResponders):
		return RegionUnreachable, "region did not answer"
	default:
		return RegionError, "region query failed"
	}
}

var _ Source = Federation{}
