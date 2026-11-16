package natscell

import (
	"errors"
)

// ErrStoreIdentity reports a JetStream store that belongs to another server
// name. JetStream derives a server's Raft node ID from its name, so reopening
// the store under a new name strands its persisted metadata peers.
var ErrStoreIdentity = errors.New("NATS store belongs to another server name")
