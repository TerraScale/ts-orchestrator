package ocireconcile

import (
	"errors"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
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
				var invalid *provider.InvalidDataError
				if !errors.As(err, &invalid) {
					t.Fatalf("classify(%d, %q, %q) = %v, want rejection error", tc.status, tc.code, tc.message, err)
				}
			}
		})
	}
}
