package cellscale

import (
	"bytes"
	"context"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrResizeRejected means the resize was confirmed rejected without mutation.
var ErrResizeRejected = errors.New("resize rejected without mutation")

// Instance is one OCI instance of a cell, named by its static node name.
// A foreign instance holds a node name without the autoscaler's tags, such
// as a placement seat: its name is taken, and nothing else about it is ours.
type Instance struct {
	ID                 string
	Name               string
	State              string
	ShapeName          string
	Shape              Shape
	AvailabilityDomain string
	Foreign            bool
}

// Running reports whether OCI runs the instance.
func (i Instance) Running() bool { return i.State == "RUNNING" }

// Cloud is the OCI boundary of one cell.
type Cloud interface {
	// List returns every instance named as a node of the cell that is not
	// terminated. A terminating instance is listed: it still holds its name.
	List(ctx context.Context) ([]Instance, error)
	// Launch creates node name from the cell template at shape. It is
	// idempotent for one name.
	Launch(ctx context.Context, name string, shape Shape) (Instance, error)
	// Resize changes the instance's flex shape; OCI restarts the instance.
	// Errors wrapping ErrResizeRejected confirm no mutation occurred, so the
	// caller can release its restart fence. Other errors may follow a mutation.
	Resize(ctx context.Context, id string, shape Shape) error
	// Terminate deletes the instance and its boot volume.
	Terminate(ctx context.Context, id string) error
}

// Members is the TerraBase side of a cell. TerraBase performs the effects;
// the autoscaler only sequences them and waits on the node's reported state.
type Members interface {
	// Replicas returns the complete, current placement inventory for the cell,
	// listing live caught-up replicas per database/shard, never top tenants.
	Replicas(ctx context.Context, node string) (ReplicaSnapshot, error)
	// Join admits a launched node into the cell's replica set.
	Join(ctx context.Context, node NodeIdentity) error
	// Drain starts moving every tenant and replica off node; the node then
	// reports StateDrained.
	Drain(ctx context.Context, node NodeIdentity) error
	// MoveTenant is the rebalancing hook: it moves a project between nodes.
	MoveTenant(ctx context.Context, project string, from, to NodeIdentity) error
}

// HTTPMembers calls the TerraBase node endpoints of the cell contract:
// POST /v1/node/join and /v1/node/drain on the node itself, and
// POST /v1/tenants/<org>/move on the tenant's node. Each hook carries the
// expected full identity; moves also carry the destination's identity.
type HTTPMembers struct {
	Client   *http.Client
	Endpoint func(node string) string
}

func (m HTTPMembers) Join(ctx context.Context, node NodeIdentity) error {
	return m.postIdentity(ctx, node, "/v1/node/join", map[string]NodeIdentity{"expected": node})
}

func (m HTTPMembers) Drain(ctx context.Context, node NodeIdentity) error {
	return m.postIdentity(ctx, node, "/v1/node/drain", map[string]NodeIdentity{"expected": node})
}

func (m HTTPMembers) MoveTenant(ctx context.Context, project string, from, to NodeIdentity) error {
	if !to.valid() {
		return errors.New("tenant move requires destination identity")
	}
	return m.postIdentity(ctx, from, "/v1/tenants/"+url.PathEscape(project)+"/move", map[string]any{
		"expected": from, "to": to.Name, "expected_target": to,
	})
}

func (m HTTPMembers) postIdentity(ctx context.Context, node NodeIdentity, path string, body any) error {
	if !node.valid() {
		return errors.New("membership mutation requires node identity")
	}
	return m.post(ctx, node.Name, path, body)
}

func (m HTTPMembers) post(ctx context.Context, node, path string, body any) error {
	client := http.Client{Timeout: 30 * time.Second}
	if m.Client != nil {
		client = *m.Client
	}
	// Preserve caller settings without following or rewriting mutation POSTs.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(m.Endpoint(node), "/")+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxPressureBytes))
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusAccepted {
		return fmt.Errorf("node %s %s: HTTP %d", node, path, response.StatusCode)
	}
	return nil
}

// RolloutGate reads a rollout status endpoint that answers
// {"in_flight": bool}. Any other answer is an error, which fails the tick:
// an unknown rollout state never acts.
func RolloutGate(client *http.Client, gate string) func(context.Context) (bool, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return func(ctx context.Context) (bool, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, gate, nil)
		if err != nil {
			return false, err
		}
		response, err := client.Do(request)
		if err != nil {
			return false, err
		}
		defer response.Body.Close()
		var status struct {
			InFlight *bool `json:"in_flight"`
		}
		if response.StatusCode != http.StatusOK {
			return false, fmt.Errorf("rollout gate: HTTP %d", response.StatusCode)
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, maxPressureBytes+1))
		if err != nil || len(body) > maxPressureBytes {
			return false, fmt.Errorf("rollout gate: unreadable or oversized answer: %v", err)
		}
		if err := jsonv2.Unmarshal(body, &status, jsonv2.RejectUnknownMembers(true)); err != nil || status.InFlight == nil {
			return false, fmt.Errorf("rollout gate: no in_flight answer: %v", err)
		}
		return *status.InFlight, nil
	}
}
