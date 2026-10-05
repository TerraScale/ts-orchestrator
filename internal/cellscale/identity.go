package cellscale

import (
	"maps"
	"reflect"
	"time"
)

// identities captures an action's original observation. Only a newly launched
// node can lack an incarnation, until its first validated pressure report.
func identities(nodes []Node) map[string]NodeIdentity {
	out := make(map[string]NodeIdentity, len(nodes))
	for _, node := range nodes {
		out[node.Name] = node.Identity()
	}
	return out
}

// transitionIdentity is the single invalidation point for replacement and
// reboot. Ticks serialize it with all evidence and effects; no predecessor
// telemetry, inventory, or action progress survives the transition.
func (c *Controller) transitionIdentity(next NodeIdentity, after time.Time) {
	old, found := c.activeIdentities[next.Name]
	if found && old == next {
		return
	}
	if found {
		if old.Incarnation != "" {
			c.retiredIncarnations[NodeIdentity{Name: old.Name, Incarnation: old.Incarnation}] = true
		}
		if old.InstanceID != next.InstanceID {
			c.retiredInstances[NodeIdentity{Name: old.Name, InstanceID: old.InstanceID}] = true
		}
		if fence, pending := c.pendingRestarts[old]; pending && old.InstanceID == next.InstanceID {
			// Preserve only the refusal associated with an ambiguous OCI
			// effect, never the old identity's readiness or resize progress.
			c.restartBarriers[old] = fence
		}
	}
	for id := range c.lastPressure {
		if id.Name == next.Name {
			delete(c.lastPressure, id)
		}
	}
	for id := range c.pendingRestarts {
		if id.Name == next.Name {
			delete(c.pendingRestarts, id)
		}
	}
	for id := range c.restartBarriers {
		if id.Name == next.Name && id.InstanceID != next.InstanceID {
			delete(c.restartBarriers, id)
		}
	}
	for id := range c.observedShapes {
		if id.Name == next.Name && id.InstanceID != next.InstanceID {
			delete(c.observedShapes, id)
		}
	}
	// A backwards controller clock cannot weaken an earlier refusal.
	if after.After(c.pressureAfter[next.Name]) {
		c.pressureAfter[next.Name] = after.Round(0)
	}
	if high := c.pressureHighWater[next.Name]; high.After(c.pressureAfter[next.Name]) {
		c.pressureAfter[next.Name] = high
	}
	c.activeIdentities[next.Name] = next
	if _, listed := c.lastMembership[next.Name]; listed {
		c.lastMembership[next.Name] = next
	}
	if previous := c.lastReplicas; previous != nil && previous.SampledAt.After(c.replicasAfter) {
		c.replicasAfter = previous.SampledAt
	}
	c.lastReplicas = nil
	c.mu.Lock()
	c.history.Want, c.history.WantSince = "", time.Time{}
	c.mu.Unlock()
	c.fenceReplicas()
}

// trackPressureIdentities must precede ANY pressure RPC and every final OCI
// mismatch return, including a replacement in a later row of the listing.
func (c *Controller) trackPressureIdentities(instances []Instance) []string {
	membership := make(map[string]NodeIdentity)
	var changedShapes []string
	for _, instance := range instances {
		if _, ok := Ordinal(c.config.Cell, instance.Name); !ok || instance.Foreign {
			continue
		}
		old, found := c.activeIdentities[instance.Name]
		if !found || old.InstanceID != instance.ID {
			after := time.Time{}
			if found {
				after = c.config.Now().Add(MaxPressureClockSkew)
			}
			c.transitionIdentity(NodeIdentity{Name: instance.Name, InstanceID: instance.ID}, after)
		}
		// OCI has no agent incarnation. This capacity witness only detects
		// changes; it cannot supply pressure, readiness or operation progress.
		shapeID := NodeIdentity{Name: instance.Name, InstanceID: instance.ID}
		if previous, known := c.observedShapes[shapeID]; known && !sameShape(previous, instance.Shape) {
			c.fenceShapePressure(c.activeIdentities[instance.Name])
			changedShapes = append(changedShapes, instance.Name)
		}
		c.observedShapes[shapeID] = instance.Shape
		membership[instance.Name] = c.activeIdentities[instance.Name]
	}
	if !maps.Equal(membership, c.lastMembership) {
		c.fenceReplicas()
	}
	c.lastMembership = membership
	return changedShapes
}

func (c *Controller) fenceShapePressure(id NodeIdentity) {
	after := c.config.Now().Add(MaxPressureClockSkew).Round(0)
	if high := c.pressureHighWater[id.Name]; high.After(after) {
		after = high
	}
	if after.After(c.pressureAfter[id.Name]) {
		c.pressureAfter[id.Name] = after
	}
	delete(c.lastPressure, id)
	if previous := c.lastReplicas; previous != nil && previous.SampledAt.After(c.replicasAfter) {
		c.replicasAfter = previous.SampledAt.Round(0)
	}
	c.lastReplicas = nil
	c.fenceReplicas()
}

// restartFor looks up a current operation or an old identity's refusal. The
// latter can only prevent effects until fresh OCI/pressure convergence.
func (c *Controller) restartFor(node string) (NodeIdentity, restartFence, bool) {
	active := c.activeIdentities[node]
	if fence, found := c.pendingRestarts[active]; found {
		return active, fence, true
	}
	for id, fence := range c.restartBarriers {
		if id.Name == node && id.InstanceID == active.InstanceID {
			return id, fence, true
		}
	}
	return NodeIdentity{}, restartFence{}, false
}

func (c *Controller) convergeRestart(instance Instance) {
	id, fence, pending := c.restartFor(instance.Name)
	if !pending || !fence.after.IsZero() || !instance.Running() || !sameShape(instance.Shape, fence.shape) {
		return
	}
	fence.after = c.config.Now().Add(MaxPressureClockSkew).Round(0)
	if floor := c.pressureAfter[instance.Name]; floor.After(fence.after) {
		fence.after = floor
	}
	if _, progress := c.pendingRestarts[id]; progress {
		c.pendingRestarts[id] = fence
	} else {
		c.restartBarriers[id] = fence
	}
}

func (c *Controller) releaseRestart(id NodeIdentity, refence ...bool) {
	released := false
	for old := range c.pendingRestarts {
		if old.Name == id.Name && old.InstanceID == id.InstanceID {
			delete(c.pendingRestarts, old)
			released = true
		}
	}
	for old := range c.restartBarriers {
		if old.Name == id.Name && old.InstanceID == id.InstanceID {
			delete(c.restartBarriers, old)
			released = true
		}
	}
	if released && (len(refence) == 0 || refence[0]) {
		c.fenceReplicas()
	}
}

func (c *Controller) pressureUsable(node string, p NodePressure) bool {
	if !c.retainPressure(node, p) {
		return false
	}
	c.releaseRestart(p.Identity())
	return true
}

// retainPressure accepts evidence for exactly one active identity. Floors and
// incarnation tombstones carry replay protection without predecessor samples.
func (c *Controller) retainPressure(node string, p NodePressure) bool {
	if p.Node != node || p.Validate() != nil || !p.Fresh(c.config.Now()) || !p.SampledAt.After(c.startedAfter) {
		return false
	}
	id := p.Identity()
	active, found := c.activeIdentities[node]
	if !found {
		return false
	}
	if id.InstanceID != active.InstanceID ||
		c.retiredIncarnations[NodeIdentity{Name: node, Incarnation: id.Incarnation}] ||
		c.retiredInstances[NodeIdentity{Name: node, InstanceID: id.InstanceID}] {
		if p.SampledAt.After(c.pressureHighWater[node]) {
			c.pressureHighWater[node] = p.SampledAt.Round(0)
		}
		if p.SampledAt.After(c.pressureAfter[node]) {
			c.pressureAfter[node] = p.SampledAt.Round(0)
		}
		return false
	}
	_, fence, restarting := c.restartFor(node)
	controlled := restarting && !fence.after.IsZero() && p.State == StateReady &&
		p.ProcessID != fence.process && p.SampledAt.After(fence.after)
	if active != id {
		// A delayed unseen incarnation cannot retire the running process.
		// Equal timestamps remain contradictory until newer evidence arrives.
		if p.SampledAt.Equal(c.pressureHighWater[node]) {
			if p.SampledAt.After(c.pressureAfter[node]) {
				c.pressureAfter[node] = p.SampledAt.Round(0)
			}
			delete(c.lastPressure, active)
			c.fenceReplicas()
			return false
		}
		if p.SampledAt.Before(c.pressureHighWater[node]) || !p.SampledAt.After(c.pressureAfter[node]) {
			return false
		}
		after := c.pressureAfter[node]
		if active.Incarnation != "" {
			if controlled {
				after = fence.after
			} else if now := c.config.Now().Add(MaxPressureClockSkew); now.After(after) {
				after = now
			}
		}
		c.transitionIdentity(id, after)
	}
	if p.SampledAt.Before(c.pressureHighWater[node]) {
		return false
	}
	if previous, exists := c.lastPressure[id]; exists {
		if p.SampledAt.Before(previous.SampledAt) {
			return false
		}
		if p.SampledAt.Equal(previous.SampledAt) && !reflect.DeepEqual(p, previous) {
			previous.State = ""
			c.lastPressure[id] = previous
			c.fenceReplicas()
			return false
		}
		if p.State != previous.State {
			c.fenceReplicas()
		}
	} else if p.State != StateReady {
		c.fenceReplicas()
	}
	if p.SampledAt.After(c.pressureHighWater[node]) {
		c.pressureHighWater[node] = p.SampledAt.Round(0)
	}
	if !p.SampledAt.After(c.pressureAfter[node]) {
		return false
	}
	if restarting && !controlled {
		return false
	}
	c.lastPressure[id] = p
	return true
}
