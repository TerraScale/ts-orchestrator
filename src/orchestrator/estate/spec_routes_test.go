package estate

import (
	"strings"
	"testing"
)

func TestDefaultEstateDeclaresRouteTables(t *testing.T) {
	spec := Default()
	if err := spec.Validate(); err != nil {
		t.Fatalf("default estate rejected: %v", err)
	}
	for _, region := range spec.Regions {
		if len(region.Network.RouteTables) == 0 {
			t.Fatalf("region %s declares no route tables", region.Code)
		}
		for _, table := range region.Network.RouteTables {
			if len(table.Routes) == 0 {
				t.Fatalf("route table %s/%s declares no routes", region.Code, table.Name)
			}
		}
	}
}

func TestRouteTableValidationRejectsUnsafeDeclarations(t *testing.T) {
	tests := []struct {
		name string
		path string
		edit func(*Spec)
	}{
		{
			name: "unknown subnet",
			path: "regions[0].network.routeTables[0].subnet",
			edit: func(spec *Spec) { spec.Regions[0].Network.RouteTables[0].Subnet = "unknown" },
		},
		{
			name: "route inside the vcn",
			path: "regions[0].network.routeTables[0].routes[0]",
			edit: func(spec *Spec) {
				spec.Regions[0].Network.RouteTables[0].Routes[0].Destination = "10.10.1.0/24"
			},
		},
		{
			name: "unsupported target",
			path: "regions[0].network.routeTables[0].routes[0]",
			edit: func(spec *Spec) { spec.Regions[0].Network.RouteTables[0].Routes[0].ViaNAT = false },
		},
		{
			name: "duplicate destination",
			path: "regions[0].network.routeTables[0].routes[2]",
			edit: func(spec *Spec) {
				table := &spec.Regions[0].Network.RouteTables[0]
				table.Routes = append(table.Routes, RouteRule{Destination: "0.0.0.0/1", ViaNAT: true})
				table.Routes = append(table.Routes, RouteRule{Destination: "0.0.0.0/1", ViaNAT: true})
			},
		},
		{
			name: "invalid destination",
			path: "regions[0].network.routeTables[0].routes[0]",
			edit: func(spec *Spec) { spec.Regions[0].Network.RouteTables[0].Routes[0].Destination = "not-a-cidr" },
		},
		{
			name: "empty routes",
			path: "regions[0].network.routeTables[0].routes",
			edit: func(spec *Spec) { spec.Regions[0].Network.RouteTables[0].Routes = nil },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := Default()
			if err := spec.Validate(); err != nil {
				t.Fatalf("default estate rejected before edit: %v", err)
			}
			tc.edit(&spec)
			err := spec.Validate()
			if err == nil {
				t.Fatal("unsafe route declaration accepted")
			}
			if !strings.Contains(err.Error(), tc.path) {
				t.Fatalf("error %q does not name %s", err.Error(), tc.path)
			}
		})
	}
}

func TestRouteTableCanonicalizesDestinations(t *testing.T) {
	spec := Default()
	spec.Regions[0].Network.RouteTables[0].Routes[0].Destination = "0.0.0.0/0"
	if err := spec.Validate(); err != nil {
		t.Fatalf("canonical default route rejected: %v", err)
	}
	spec.Regions[0].Network.RouteTables[0].Routes[0].Destination = "128.0.0.0/1"
	spec.Regions[0].Network.RouteTables[0].Routes = append(
		spec.Regions[0].Network.RouteTables[0].Routes,
		RouteRule{Destination: "0.0.0.0/1", ViaNAT: true},
	)
	if err := spec.Validate(); err != nil {
		t.Fatalf("split default routes rejected: %v", err)
	}
}
