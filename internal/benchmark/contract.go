// Package benchmark runs the shared TS-761 client contract on isolated capacity.
package benchmark

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"slices"
	"time"
)

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
var imagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}$`)
var workerPathPattern = regexp.MustCompile(`^/[A-Za-z0-9_./-]+$`)
var idPattern = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
var languages = []string{"go", "dotnet", "rust"}
var operations = []string{"doc.create", "doc.get", "doc.update", "doc.delete", "query.simple", "query.indexed", "txn.multi"}

const MaxRun = 15 * time.Minute

type Workload struct {
	Name        string `json:"name"`
	Duration    int    `json:"duration_s"`
	Warmup      int    `json:"warmup_s"`
	Concurrency int    `json:"concurrency"`
	Dataset     struct {
		Documents int `json:"documents"`
		DocSize   int `json:"doc_size_bytes"`
	} `json:"dataset"`
	Mix []struct {
		Op      string  `json:"op"`
		Weight  float64 `json:"weight"`
		DocSize int     `json:"doc_size_bytes,omitempty"`
	} `json:"mix"`
	Targets struct {
		P99 float64 `json:"p99_ms"`
	} `json:"targets"`
}

func (w Workload) Validate() error {
	if !namePattern.MatchString(w.Name) || w.Duration < 30 || w.Duration > 840 || w.Warmup < 0 || w.Warmup > 300 || w.Duration+w.Warmup > 840 || w.Concurrency < 1 || w.Concurrency > 65536 || w.Dataset.Documents < 1 || w.Dataset.Documents > 10000000 || w.Dataset.DocSize < 1 || w.Dataset.DocSize > 4<<20 || !finite(w.Targets.P99) || w.Targets.P99 <= 0 || len(w.Mix) == 0 || len(w.Mix) > 7 {
		return errors.New("invalid workload or unbounded duration; duration must be 30..840 seconds and duration + warmup <= 840")
	}
	seen := map[string]bool{}
	for _, op := range w.Mix {
		if !slices.Contains(operations, op.Op) || seen[op.Op] || !finite(op.Weight) || op.Weight <= 0 || op.DocSize < 0 || op.DocSize > 4<<20 {
			return errors.New("invalid workload mix")
		}
		seen[op.Op] = true
	}
	return nil
}

type Sample struct {
	Type       string                     `json:"type,omitempty"`
	TS         time.Time                  `json:"ts,omitempty"`
	Client     string                     `json:"client"`
	SDK        string                     `json:"sdk,omitempty"`
	SDKVersion string                     `json:"sdk_version,omitempty"`
	Region     string                     `json:"region"`
	Op         string                     `json:"op,omitempty"`
	Count      uint64                     `json:"count,omitempty"`
	Errors     uint64                     `json:"errors,omitempty"`
	P50        float64                    `json:"p50_us,omitempty"`
	P95        float64                    `json:"p95_us,omitempty"`
	P99        float64                    `json:"p99_us,omitempty"`
	Max        float64                    `json:"max_us,omitempty"`
	Workload   string                     `json:"workload,omitempty"`
	OpsPerS    float64                    `json:"ops_per_s,omitempty"`
	ErrorRate  float64                    `json:"error_rate,omitempty"`
	PerOp      map[string]json.RawMessage `json:"per_op,omitempty"`
}

func (s Sample) Validate(client, region, workload string) error {
	return s.validate(client, region, workload, time.Now())
}
func (s Sample) validate(client, region, workload string, now time.Time) error {
	if s.Client != client || s.Region != region {
		return errors.New("client result identity mismatch")
	}
	if s.Type == "summary" {
		if s.Workload != workload || !finite(s.OpsPerS) || s.OpsPerS < 0 || !finite(s.ErrorRate) || s.ErrorRate < 0 || s.ErrorRate > 1 || len(s.PerOp) == 0 {
			return errors.New("invalid client summary")
		}
		return nil
	}
	if s.Type != "" || s.TS.IsZero() || s.TS.After(now.Add(2*time.Second)) || s.TS.Before(now.Add(-MaxRun-time.Minute)) || !slices.Contains(operations, s.Op) || s.SDK == "" || s.SDKVersion == "" || s.Errors > s.Count {
		return errors.New("invalid per-second client sample")
	}
	if !finite(s.P50) || !finite(s.P95) || !finite(s.P99) || !finite(s.Max) || s.P50 < 0 || s.P50 > s.P95 || s.P95 > s.P99 || s.P99 > s.Max {
		return errors.New("invalid latency percentiles")
	}
	return nil
}

func finite(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }

func newID() string {
	var data [16]byte
	rand.Read(data[6:])
	stamp := uint64(time.Now().UnixMilli())
	for i := 5; i >= 0; i-- {
		data[i] = byte(stamp)
		stamp >>= 8
	}
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var out [26]byte
	var acc uint32
	bits, index := uint(2), 0
	for _, value := range data {
		acc = acc<<8 | uint32(value)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out[index] = alphabet[(acc>>bits)&31]
			index++
		}
	}
	return string(out[:])
}
