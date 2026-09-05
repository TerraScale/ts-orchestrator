package vmqual

// StackSnapshot is a synchronized copy of the admitted VM handles and topology.
// Observers may inspect handles without holding the stack lifecycle mutex.
type StackSnapshot struct {
	Guests  []Guest
	VMs     map[string]VM
	Started bool
}

func (s *Stack) Snapshot() StackSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot := StackSnapshot{Guests: append([]Guest(nil), s.guests...), VMs: make(map[string]VM, len(s.vms)), Started: s.started}
	for id, vm := range s.vms {
		snapshot.VMs[id] = vm
	}
	return snapshot
}

// Config returns a synchronized copy of the stack's configuration.
func (s *Stack) Config() StackConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	config := s.config
	config.Guests = append([]Guest(nil), config.Guests...)
	return config
}
