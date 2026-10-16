package ociregion

import (
	"errors"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/sdkcli"
)

func TestSDKReadOfARegionOutsideTheCatalogFallsBackOrFailsNamed(t *testing.T) {
	read := []any{"os", "ns", "get"}
	region := Object{"region": "xx-nowhere-1"}
	auto := &Engine{Context: t.Context(), Backend: sdkcli.BackendAuto}
	value, served := auto.sdkOCI(read, region)
	if served || value != nil {
		t.Fatalf("auto served a non-catalog region in-binary: %v %v", value, served)
	}
	strict := &Engine{Context: t.Context(), Backend: sdkcli.BackendSDK}
	_, err := capture(func() any {
		value, _ := strict.sdkOCI(read, region)
		return value
	})
	var failure Failure
	if !errors.As(err, &failure) || !strings.Contains(failure.Message, "xx-nowhere-1") {
		t.Fatalf("sdk backend error = %v, want a named operational failure", err)
	}
}

func TestSDKHeadKeepsTheCauseAndRepanicsProgrammingErrors(t *testing.T) {
	strict := &Engine{Context: t.Context(), Backend: sdkcli.BackendSDK}
	_, err := capture(func() any {
		value, _ := strict.sdkHead("ns", "bucket", "key", "xx-nowhere-1")
		return value
	})
	var failure Failure
	if !errors.As(err, &failure) || !strings.Contains(failure.Message, "key is deleted: ") ||
		!strings.Contains(failure.Message, "xx-nowhere-1") {
		t.Fatalf("HEAD failure = %v, want the recast message with its cause", err)
	}
}
