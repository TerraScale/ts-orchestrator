package membership

import "time"

// Topology is the regional membership address inside the control-plane KV.
type Topology struct {
	Cell          string
	Replicas      int
	Instance      string
	RuntimeBucket string
}

// NewTopology binds a membership publisher to one regional controller slot.
func NewTopology(cell string, replicas int, instance, runtimeBucket string) *Topology {
	return &Topology{Cell: cell, Replicas: replicas, Instance: instance, RuntimeBucket: runtimeBucket}
}

// AuthoritySnapshot is the authority state a controller publishes with its
// membership lease.
type AuthoritySnapshot struct {
	State          string
	IsLeader       bool
	Epoch          int64
	KvRevision     int64
	LeaseExpiresAt *time.Time
	ObservedAt     time.Time
	Error          *string
}

// Ready reports whether the authority observation is current and leased.
func (s AuthoritySnapshot) Ready() bool {
	if s.State != "leader" && s.State != "follower" {
		return false
	}
	if s.Error != nil || s.ObservedAt.Before(time.Now().UTC().Add(-30*time.Second)) {
		return false
	}
	return s.LeaseExpiresAt != nil && s.LeaseExpiresAt.After(time.Now().UTC())
}

type errorBox struct{ err error }
