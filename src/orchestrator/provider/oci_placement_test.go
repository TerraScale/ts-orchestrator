package provider

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckPlacementWidening(t *testing.T) {
	prior := PlacementLock{Regions: []string{"gru", "sfo"}}
	cases := []struct {
		name    string
		updated []string
		wantErr bool
	}{
		{name: "identical", updated: []string{"gru", "sfo"}},
		{name: "narrowing is allowed", updated: []string{"gru"}},
		{name: "widening is refused", updated: []string{"gru", "fra"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckPlacementWidening(prior, PlacementLock{Regions: tc.updated})
			if !tc.wantErr && err != nil {
				t.Fatalf("CheckPlacementWidening(%v) = %v, want nil", tc.updated, err)
			}
			var refused *PlacementError
			if tc.wantErr && !errors.As(err, &refused) {
				t.Fatalf("CheckPlacementWidening(%v) = %v, want placement error", tc.updated, err)
			}
		})
	}
}

func TestCheckPlacement(t *testing.T) {
	lock := PlacementLock{Regions: []string{"gru", "sfo", "fra"}}
	hosts := map[string]int{"gru": 2, "sfo": 3, "fra": 1}
	cases := []struct {
		name      string
		candidate []string
		wantErr   string
	}{
		{name: "in lock and above floor", candidate: []string{"gru", "sfo"}},
		{name: "outside lock refused", candidate: []string{"gru", "iad"}, wantErr: "outside the placement lock"},
		{name: "below host floor refused", candidate: []string{"fra"}, wantErr: "placement requires 2"},
		{name: "duplicate candidate refused", candidate: []string{"gru", "gru"}, wantErr: "duplicated"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckPlacement(lock, tc.candidate, hosts)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("CheckPlacement(%v) = %v, want nil", tc.candidate, err)
				}
				return
			}
			var refused *PlacementError
			if !errors.As(err, &refused) || !strings.Contains(refused.Rule, tc.wantErr) {
				t.Fatalf("CheckPlacement(%v) = %v, want rule containing %q", tc.candidate, err, tc.wantErr)
			}
		})
	}
}

func TestNewPlacementLock(t *testing.T) {
	if _, err := NewPlacementLock(nil); err == nil {
		t.Fatal("empty lock accepted")
	}
	if _, err := NewPlacementLock([]string{"gru", "gru"}); err == nil {
		t.Fatal("duplicate lock accepted")
	}
	if _, err := NewPlacementLock([]string{"GRU"}); err == nil {
		t.Fatal("non-canonical lock accepted")
	}
	lock, err := NewPlacementLock([]string{"sfo", "gru"})
	if err != nil {
		t.Fatalf("valid lock rejected: %v", err)
	}
	regions := lock.PlacementLockRegions()
	if regions[0] != "gru" || regions[1] != "sfo" {
		t.Fatalf("PlacementLockRegions() = %v, want sorted codes", regions)
	}
}
