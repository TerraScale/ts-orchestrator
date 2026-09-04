package cloudflare

import (
	"strings"
	"sync"
	"time"
)

// FaultStep is one deterministic response in a Fault script. A Commit step
// applies a mutation before returning the scripted status, modelling a lost
// response/indeterminate provider outcome. Drop closes a hijacked connection
// where the test server transport permits it.
type FaultStep struct {
	Status  int
	Code    int
	Message string
	Body    any
	Headers map[string]string
	Delay   time.Duration
	Drop    bool
	Commit  bool
}

// Fault describes a sequence matched by method and path. Path matching is
// exact unless it ends in *, in which case it is a prefix match. A zero Calls
// value consumes every matching request; otherwise the script stops after the
// specified number of requests.
type Fault struct {
	Method string
	Path   string
	Calls  int
	Steps  []FaultStep
	// Response is shorthand for a one-step script.
	Response *FaultStep
}

// FaultScript and FaultResponse are readable aliases for test fixtures.
type FaultScript = Fault
type FaultResponse = FaultStep

type faultEntry struct {
	Fault
	used, step int
}
type faultBook struct {
	mu      sync.Mutex
	entries []faultEntry
}

func newFaultBook(in []Fault) *faultBook {
	out := &faultBook{entries: make([]faultEntry, 0, len(in))}
	for _, f := range in {
		if len(f.Steps) == 0 && f.Response != nil {
			f.Steps = []FaultStep{*f.Response}
		}
		out.entries = append(out.entries, faultEntry{Fault: f})
	}
	return out
}

func (b *faultBook) next(method, path string) (FaultStep, bool) {
	if b == nil {
		return FaultStep{}, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := range b.entries {
		e := &b.entries[i]
		if e.Method != "" && !strings.EqualFold(e.Method, method) {
			continue
		}
		if e.Path != "" && !(e.Path == path || strings.HasSuffix(e.Path, "*") && strings.HasPrefix(path, strings.TrimSuffix(e.Path, "*"))) {
			continue
		}
		if e.Calls > 0 && e.used >= e.Calls {
			continue
		}
		if len(e.Steps) == 0 {
			continue
		}
		step := e.Steps[e.step%len(e.Steps)]
		e.step++
		e.used++
		return step, true
	}
	return FaultStep{}, false
}

// SetFaultScript replaces the deterministic fault sequence. It is safe to
// call between requests, and intentionally only affects this local endpoint.
func (s *Server) SetFaultScript(script []Fault) {
	if s == nil {
		return
	}
	s.faults = newFaultBook(script)
}

// AddFault appends one script to the endpoint.
func (s *Server) AddFault(f Fault) {
	if s == nil {
		return
	}
	if s.faults == nil {
		s.faults = newFaultBook(nil)
	}
	s.faults.mu.Lock()
	defer s.faults.mu.Unlock()
	if len(f.Steps) == 0 && f.Response != nil {
		f.Steps = []FaultStep{*f.Response}
	}
	s.faults.entries = append(s.faults.entries, faultEntry{Fault: f})
}
