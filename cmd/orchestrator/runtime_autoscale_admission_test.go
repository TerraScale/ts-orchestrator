package main

import (
	"context"
	"testing"
)

func TestProductionAutoscaleAdmissionRequiresAllConfiguredPorts(t *testing.T) {
	validSource := runtimeAutoscaleSource{}
	validApply := func(string, int) error { return nil }
	valid := productionGlobalWorkerConfig{
		AutoscaleRequired:   true,
		AutoscaleSource:     &validSource,
		AutoscaleRegions:    []string{"gru"},
		ApplyScaleOutTarget: validApply,
	}
	if err := validateProductionAutoscaleConfig(valid); err != nil {
		t.Fatal(err)
	}
	for name, config := range map[string]productionGlobalWorkerConfig{
		"missing source":   {AutoscaleRequired: true, AutoscaleRegions: []string{"gru"}, ApplyScaleOutTarget: validApply},
		"missing callback": {AutoscaleRequired: true, AutoscaleSource: &validSource, AutoscaleRegions: []string{"gru"}},
		"missing regions":  {AutoscaleRequired: true, AutoscaleSource: &validSource, ApplyScaleOutTarget: validApply},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateProductionAutoscaleConfig(config); err == nil {
				t.Fatal("incomplete autoscale admission was accepted")
			}
		})
	}
}

func TestProductionAutoscaleContextRejectsUnavailableHandoff(t *testing.T) {
	if _, ok := productionAutoscaleFromContext(context.Background()); ok {
		t.Fatal("empty context admitted autoscale")
	}
	if _, ok := productionAutoscaleFromContext(withProductionAutoscaleWiring(context.Background(), productionAutoscaleWiring{
		Source: &runtimeAutoscaleSource{}, Regions: []string{"gru"}, Apply: func(string, int) error { return nil },
	})); !ok {
		t.Fatal("complete autoscale handoff was rejected")
	}
	if _, ok := productionAutoscaleFromContext(withProductionAutoscaleWiring(context.Background(), productionAutoscaleWiring{
		Source: &runtimeAutoscaleSource{}, Regions: []string{"gru"}, Apply: nil,
	})); ok {
		t.Fatal("incomplete autoscale handoff was admitted")
	}
}
