package ocireconcile

import (
	"errors"
	"net/http"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"testing"
)

func TestClassifyOCIRejection(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		code        string
		message     string
		wantQuota   bool
		wantShape   bool
		wantUnknown bool
		wantReject  bool
	}{
		{name: "rate limited", status: 429, wantQuota: true},
		{name: "limit exceeded code", status: 400, code: "LimitExceeded", wantQuota: true},
		{name: "quota exceeded code", status: 400, code: "QuotaExceeded", wantQuota: true},
		{name: "ampere capacity out", status: 500, message: "Out of host capacity.", wantShape: true},
		{name: "noncanonical capacity message", status: 500, code: "OutOfHostCapacity", message: "out of host capacity", wantUnknown: true},
		{name: "capacity phrase embedded", status: 500, message: "out of host capacity in AD-1", wantUnknown: true},
		{name: "capacity on other status", status: 503, message: "Out of host capacity.", wantUnknown: true},
		{name: "generic internal error", status: 500, code: "InternalError", message: "boom", wantUnknown: true},
		{name: "not authorized", status: 401, code: "NotAuthenticated", wantReject: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := classifyOCIRejection(tc.status, tc.code, tc.message)
			var quota *OCIQuotaError
			var shape *OCIShapeCapacityError
			var unknown *provider.ProviderOutcomeUnknownError
			switch {
			case tc.wantQuota:
				if !errors.As(err, &quota) {
					t.Fatalf("classify(%d, %q, %q) = %v, want quota error", tc.status, tc.code, tc.message, err)
				}
			case tc.wantShape:
				if !errors.As(err, &shape) {
					t.Fatalf("classify(%d, %q, %q) = %v, want shape capacity error", tc.status, tc.code, tc.message, err)
				}
			case tc.wantUnknown:
				if !errors.As(err, &unknown) {
					t.Fatalf("classify(%d, %q, %q) = %v, want unknown outcome", tc.status, tc.code, tc.message, err)
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

func TestClassifyOCIRejectionCapacityArgument(t *testing.T) {
	for _, problemType := range []string{"", "OUT_OF_CAPACITY"} {
		err := classifyOCIRejectionWithProblemType(http.StatusInternalServerError, "", "  OUT OF HOST CAPACITY. ", problemType)
		var capacity *OCIShapeCapacityError
		if !errors.As(err, &capacity) {
			t.Fatalf("problem type %q: classify = %v, want capacity error", problemType, err)
		}
	}
	err := classifyOCIRejectionWithProblemType(http.StatusInternalServerError, "", "Out of host capacity.", "OTHER")
	var unknown *provider.ProviderOutcomeUnknownError
	if !errors.As(err, &unknown) {
		t.Fatalf("wrong problem type: classify = %v, want unknown outcome", err)
	}
}
