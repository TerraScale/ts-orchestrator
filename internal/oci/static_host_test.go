package oci

import (
	"errors"
	"testing"
)

func TestObserveStaticHostAcceptsOnlyAnUnmanagedRunningFleetInstance(t *testing.T) {
	config, intent := testRegionConfig()
	provider := newFakeProvider(config)
	fleet, err := newTestFleet(config, intent, provider, newFakeJournal(), &fakeFencer{snapshot: writableSnapshot()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	static := CloudInstance{ID: "ocid1.instance.oc1.sa-saopaulo-1.static", PrivateIP: "10.251.0.21",
		CompartmentID: config.CompartmentID, AvailabilityDomain: config.AvailabilityDomain,
		FaultDomain: "FAULT-DOMAIN-1", LifecycleState: "RUNNING",
		FreeformTags: map[string]string{tagOwner: "ts-470-gru-rebuild-2", tagResource: "terrabase-host", tagHostNode: "gru-1-db-1"}}
	observer := fleet.(StaticHostObserver)
	provider.instances[static.ID] = static
	if got, err := observer.ObserveStaticHost(t.Context(), static.ID, "gru-1-db-1"); err != nil || got.PrivateIP != "10.251.0.21" {
		t.Fatalf("ObserveStaticHost() = %+v, %v", got, err)
	}
	for name, mutate := range map[string]func(*CloudInstance){
		"other compartment":    func(i *CloudInstance) { i.CompartmentID = config.ImageCompartmentID },
		"unplanned fault":      func(i *CloudInstance) { i.FaultDomain = "FAULT-DOMAIN-3" },
		"stopped":              func(i *CloudInstance) { i.LifecycleState = "STOPPED" },
		"managed launch":       func(i *CloudInstance) { i.FreeformTags[tagManagedBy] = managedByValue },
		"managed create key":   func(i *CloudInstance) { i.FreeformTags[tagCreateKey] = "th-a" },
		"other node":           func(i *CloudInstance) { i.FreeformTags[tagHostNode] = "gru-1-db-2" },
		"no private address":   func(i *CloudInstance) { i.PrivateIP = "" },
		"other availability":   func(i *CloudInstance) { i.AvailabilityDomain = "sa-saopaulo-1-AD-2" },
		"untagged static host": func(i *CloudInstance) { delete(i.FreeformTags, tagHostNode) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneCloudInstance(static)
			mutate(&candidate)
			provider.instances[static.ID] = candidate
			if _, err := observer.ObserveStaticHost(t.Context(), static.ID, "gru-1-db-1"); !errors.Is(err, ErrForeignResource) {
				t.Fatalf("accepted %s: %v", name, err)
			}
		})
	}
}
