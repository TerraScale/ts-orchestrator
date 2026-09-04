package provider

import (
	"errors"
	"strings"
	"testing"
)

func TestClassifyOCIRejection(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		code       string
		message    string
		wantQuota  bool
		wantShape  bool
		wantReject bool
	}{
		{name: "rate limited", status: 429, wantQuota: true},
		{name: "limit exceeded code", status: 400, code: "LimitExceeded", wantQuota: true},
		{name: "quota exceeded code", status: 400, code: "QuotaExceeded", wantQuota: true},
		{name: "ampere capacity out", status: 500, message: "Out of host capacity.", wantShape: true},
		{name: "capacity out lowercase", status: 500, message: "out of host capacity in AD-1", wantShape: true},
		{name: "generic internal error", status: 500, code: "InternalError", message: "boom", wantReject: true},
		{name: "not authorized", status: 401, code: "NotAuthenticated", wantReject: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := classifyOCIRejection(tc.status, tc.code, tc.message)
			var quota *OCIQuotaError
			var shape *OCIShapeCapacityError
			switch {
			case tc.wantQuota:
				if !errors.As(err, &quota) {
					t.Fatalf("classify(%d, %q, %q) = %v, want quota error", tc.status, tc.code, tc.message, err)
				}
			case tc.wantShape:
				if !errors.As(err, &shape) {
					t.Fatalf("classify(%d, %q, %q) = %v, want shape capacity error", tc.status, tc.code, tc.message, err)
				}
			default:
				var invalid *InvalidDataError
				if !errors.As(err, &invalid) {
					t.Fatalf("classify(%d, %q, %q) = %v, want rejection error", tc.status, tc.code, tc.message, err)
				}
			}
		})
	}
}

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
