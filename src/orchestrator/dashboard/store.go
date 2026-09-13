package dashboard

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"time"
)

type Store struct {
	mu          sync.RWMutex
	state       State
	subscribers map[chan State]struct{}
}

func NewStore(initial State) *Store {
	return &Store{state: cloneState(initial), subscribers: make(map[chan State]struct{})}
}
func (s *Store) Snapshot() State { s.mu.RLock(); defer s.mu.RUnlock(); return cloneState(s.state) }
func (s *Store) Set(next State) {
	s.mu.Lock()
	if sameObservation(s.state, next) {
		s.mu.Unlock()
		return
	}
	next.Version = s.state.Version + 1
	if next.ObservedAt.IsZero() {
		next.ObservedAt = time.Now().UTC()
	}
	next = cloneState(next)
	s.state = next
	for ch := range s.subscribers {
		select {
		case ch <- next:
		default:
		}
	}
	s.mu.Unlock()
}
func (s *Store) Subscribe(ctx context.Context) <-chan State {
	ch := make(chan State, 1)
	s.mu.Lock()
	s.subscribers[ch] = struct{}{}
	current := cloneState(s.state)
	s.mu.Unlock()
	ch <- current
	go func() { <-ctx.Done(); s.mu.Lock(); delete(s.subscribers, ch); close(ch); s.mu.Unlock() }()
	return ch
}

func LoadFile(path string) (State, error) {
	if path == "" {
		return State{}, errors.New("dashboard state file is empty")
	}
	const maxStateFile = 16 << 20
	info, err := os.Stat(path)
	if err != nil {
		return State{}, err
	}
	if info.Size() > maxStateFile {
		return State{}, fmt.Errorf("dashboard state file exceeds %d bytes", maxStateFile)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return State{}, err
	}
	var state State
	if err := json.Unmarshal(b, &state); err != nil {
		return State{}, err
	}
	return state, nil
}

func sameObservation(a, b State) bool {
	a.Version, b.Version = 0, 0
	return reflect.DeepEqual(a, b)
}

func cloneState(in State) State {
	in.Regions = append([]Region(nil), in.Regions...)
	in.Nodes = append([]Node(nil), in.Nodes...)
	in.Rollouts = append([]Rollout(nil), in.Rollouts...)
	in.Events = append([]Event(nil), in.Events...)
	return in
}
