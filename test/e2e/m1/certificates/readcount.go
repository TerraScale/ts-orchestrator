package main

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
)

type storeReads struct{ token atomic.Uint64 }

func (s *storeReads) Noticef(string, ...any) {}
func (s *storeReads) Warnf(string, ...any)   {}
func (s *storeReads) Fatalf(string, ...any)  {}
func (s *storeReads) Errorf(string, ...any)  {}
func (s *storeReads) Debugf(string, ...any)  {}
func (s *storeReads) Tracef(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	if strings.Contains(line, "<<-") && strings.Contains(line, ".GET.KV_edge-cert-tokens") {
		s.token.Add(1)
	}
}
func (s *storeReads) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_, _ = fmt.Fprint(w, s.token.Load())
}
