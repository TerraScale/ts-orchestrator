// Package capacity exposes read-only resource usage for benchmark windows.
package capacity

import (
	"errors"
	"time"
)

const Retention = time.Hour

type Stats struct {
	Mean          float64   `json:"mean"`
	Min           float64   `json:"min"`
	Max           float64   `json:"max"`
	Samples       int       `json:"samples"`
	From          time.Time `json:"from"`
	To            time.Time `json:"to"`
	Complete      bool      `json:"complete"`
	MaxUpperBound *float64  `json:"max_upper_bound,omitempty"`
}

type Resource struct {
	Usage    *Stats `json:"usage"`
	Request  *Stats `json:"request"`
	Limit    *Stats `json:"limit"`
	Headroom *Stats `json:"headroom"`
}

type Row struct {
	Node        string   `json:"node,omitempty"`
	Service     string   `json:"service,omitempty"`
	Environment string   `json:"environment,omitempty"`
	CPU         Resource `json:"cpu_cores"`
	Memory      Resource `json:"memory_bytes"`
}

type Usage struct {
	Region    string    `json:"region"`
	From      time.Time `json:"from"`
	To        time.Time `json:"to"`
	Complete  bool      `json:"complete"`
	Truncated bool      `json:"truncated"`
	Nodes     []Row     `json:"nodes"`
	Services  []Row     `json:"services"`
	Replicas  []Row     `json:"replicas"`
	Missing   []string  `json:"missing"`
	Gaps      []Gap     `json:"gaps,omitempty"`
}

type Gap struct {
	Node        string    `json:"node,omitempty"`
	Environment string    `json:"environment,omitempty"`
	From        time.Time `json:"from"`
	To          time.Time `json:"to"`
	Reason      string    `json:"reason"`
}

func ValidateWindow(region string, from, to, now time.Time) error {
	if region != "gru" && region != "sjc" {
		return errors.New("region must be gru or sjc")
	}
	if from.IsZero() || !from.Before(to) || from.Before(now.Add(-Retention)) || to.After(now.Add(5*time.Second)) {
		return errors.New("from/to must be an increasing RFC3339 window within the last hour")
	}
	return nil
}
