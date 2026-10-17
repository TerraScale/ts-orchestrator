//go:build linux

package app

import (
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

func TestNativeCanaryRejectsUnsealedAuthority(t *testing.T) {
	if (*rootNativeCanaryAdmission)(nil).guard(t.Context()) == nil {
		t.Fatal("nil native canary seal accepted")
	}
	if new(rootNativeCanaryAdmission).guard(t.Context()) == nil {
		t.Fatal("zero native canary seal accepted")
	}
	service := new(rootWorkloadCredentials)
	receipt, err := service.MaterializeNativeCanary(t.Context(), rootoci.Call{}, rootoci.NativeCanaryRequest{})
	if err == nil || receipt.Value != "" || !receipt.ExpiresAt.IsZero() {
		t.Fatal("unadmitted native operation returned material", err)
	}
}
