// Command add-region is the I-5 single-command region bring-up: one call
// takes an empty OCI region to serving members. It reuses the declared
// estate types for what must exist and the provider bootstrap stages for
// how OCI gets there; it never reimplements a reconciler.
//
// With --dry-run it renders the runbook (stages, members, co-hosted
// control, object storage with lifecycle rules, Litestream targets, routes,
// probes, and the region-scoped reconcile actions) and changes nothing.
// Without --dry-run it validates the same estate slice and delegates to
// the OCI bootstrap stages, which fail loudly without owner credentials.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	"terrascale.tech/orchestrator/src/orchestrator/reconcile"
)

// addRegionLitestreamPurpose is the estate bucket purpose carrying
// Litestream segments. The D-29 tiering (24 h to Infrequent Access, 7 days
// to Archive) rides that bucket's lifecycle rules.
const addRegionLitestreamPurpose = "database-backup"

// addRegionStages is the converge order one add-region run follows: the
// provider bootstrap stages first, then the edge state the reconcile loop
// owns (routes, probes). The order is part of the runbook contract.
var addRegionStages = []string{"network", "vault", "buckets", "hosts", "volumes", "routes", "probes"}

var addRegionCodePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`)

// runAddRegionBootstrap executes the OCI stages for one region. It is a
// variable so dry-run-adjacent tests can stub the provider boundary; the
// reconcilers themselves are never replaced here.
var runAddRegionBootstrap = provider.RunOCIBootstrapFromEnvironment

// addRegionRunbook is the --dry-run output: the complete I-5 runbook for
// one region. Buckets, routes, and certificates reuse the estate types
// verbatim so the runbook cannot drift from the declaration.
type addRegionRunbook struct {
	Command           string             `json:"command"`
	Region            string             `json:"region"`
	OCIRegion         string             `json:"ociRegion"`
	EstateVersion     uint32             `json:"estateVersion"`
	Stages            []string           `json:"stages"`
	Members           addRegionMembers   `json:"members"`
	Control           addRegionControl   `json:"control"`
	ObjectStorage     []estate.Bucket    `json:"objectStorage"`
	LitestreamTargets []estate.Bucket    `json:"litestreamTargets"`
	Routes            addRegionRoutes    `json:"routes"`
	Probes            addRegionProbes    `json:"probes"`
	Actions           []reconcile.Action `json:"actions"`
}

type addRegionMembers struct {
	Count         uint16 `json:"count"`
	PrimaryShape  string `json:"primaryShape"`
	FallbackShape string `json:"fallbackShape"`
	OCPUs         uint16 `json:"ocpus"`
	MemoryGiB     uint16 `json:"memoryGiB"`
	BootVolumeGiB uint16 `json:"bootVolumeGiB"`
	DataVolumeGiB uint32 `json:"dataVolumeGiB"`
}

type addRegionControl struct {
	Mode     string `json:"mode"`
	Replicas uint16 `json:"replicas"`
}

type addRegionRoutes struct {
	DNSRecords   []estate.DNSRecord   `json:"dnsRecords"`
	WorkerRoutes []estate.WorkerRoute `json:"workerRoutes"`
}

type addRegionProbeKV struct {
	Map   string `json:"map"`
	Key   string `json:"key"`
	Value string `json:"value"`
}

type addRegionProbes struct {
	KV           []addRegionProbeKV   `json:"kv"`
	Certificates []estate.Certificate `json:"certificates"`
	MemberFloor  int                  `json:"memberFloor"`
}

// runAddRegion provisions one declared region from an empty OCI region to
// serving members. Dry runs render the runbook; real runs delegate to the
// OCI bootstrap stages after the same estate validation.
func runAddRegion(ctx context.Context, args []string, lookup envLookup, output io.Writer) error {
	if ctx == nil {
		return errors.New("add-region: context is nil")
	}
	code, dryRun, err := parseAddRegionArgs(args)
	if err != nil {
		return err
	}
	spec, region, err := lookupAddRegionRegion(code)
	if err != nil {
		return err
	}
	if err := checkAddRegionFloor(region); err != nil {
		return err
	}
	if dryRun {
		if output == nil {
			return errors.New("add-region: runbook output is nil")
		}
		return renderAddRegionRunbook(spec, region, output)
	}
	if lookup == nil {
		return errors.New("add-region: environment lookup is nil")
	}
	return runAddRegionBootstrap(ctx, lookup, provider.BootstrapRequest{Region: region}, output)
}

// parseAddRegionArgs accepts `add-region <code>` and
// `add-region <code> --dry-run`. The code is canonicalized to the estate's
// lowercase form; anything flag-shaped is rejected here so credential-like
// arguments are never echoed.
func parseAddRegionArgs(args []string) (string, bool, error) {
	if len(args) < 2 || args[0] != "add-region" {
		return "", false, errors.New("add-region: region code is required")
	}
	if len(args) > 3 {
		return "", false, errors.New("add-region: command accepts only a region code and --dry-run")
	}
	code := strings.ToLower(strings.TrimSpace(args[1]))
	if !validAddRegionCode(code) {
		return "", false, errors.New("add-region: region code is invalid")
	}
	if len(args) == 2 {
		return code, false, nil
	}
	if args[2] != dryRunFlag {
		return "", false, errors.New("add-region: command accepts only a region code and --dry-run")
	}
	return code, true, nil
}

func validAddRegionCode(code string) bool {
	return code != "" && len(code) <= 63 && addRegionCodePattern.MatchString(code)
}

// lookupAddRegionRegion resolves a code against the declared estate. A code
// with no estate entry is refused: adding a region is one estate entry plus
// a release, never an invented declaration at the command line.
func lookupAddRegionRegion(code string) (estate.Spec, estate.Region, error) {
	normalized := strings.ToLower(strings.TrimSpace(code))
	if !validAddRegionCode(normalized) {
		return estate.Spec{}, estate.Region{}, errors.New("add-region: region code is invalid")
	}
	spec := estate.Default()
	if err := spec.Validate(); err != nil {
		return estate.Spec{}, estate.Region{}, err
	}
	for _, region := range spec.Regions {
		if region.Code == normalized {
			return spec, region, nil
		}
	}
	return estate.Spec{}, estate.Region{}, errors.New("add-region: unknown region " + normalized + ": declare it in the estate first")
}

// checkAddRegionFloor enforces the D-65 estate shape (two member hosts with
// a co-hosted control replica) that placement also requires: a region below
// the member floor is refused, never partially built.
func checkAddRegionFloor(region estate.Region) error {
	if region.Members.Count < provider.PlacementMinimumMemberHosts {
		return fmt.Errorf("add-region %s refused: region has %d member hosts, placement requires %d", region.Code, region.Members.Count, provider.PlacementMinimumMemberHosts)
	}
	if region.Members.ControlReplicas != 1 {
		return fmt.Errorf("add-region %s refused: region must co-host one launch control replica", region.Code)
	}
	return nil
}

// renderAddRegionRunbook writes the deterministic I-5 runbook for one
// region: stages, serving members, co-hosted control, object storage with
// lifecycle rules, Litestream targets, routes, probes, and the
// region-scoped reconcile actions an empty OCI region needs. It resolves no
// credentials and makes no provider calls.
func renderAddRegionRunbook(spec estate.Spec, region estate.Region, output io.Writer) error {
	book, err := buildAddRegionRunbook(spec, region)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(book)
}

func buildAddRegionRunbook(spec estate.Spec, region estate.Region) (addRegionRunbook, error) {
	if err := spec.Validate(); err != nil {
		return addRegionRunbook{}, err
	}
	if err := checkAddRegionFloor(region); err != nil {
		return addRegionRunbook{}, err
	}
	// Prove the declared buckets render to provider lifecycle specs before
	// the runbook claims them: object storage with lifecycle rules is a
	// precondition, not an aspiration.
	for _, bucket := range region.Buckets {
		if _, err := provider.LifecycleRuleSpecs(bucket); err != nil {
			return addRegionRunbook{}, err
		}
	}
	declared, err := reconcile.Declared(spec)
	if err != nil {
		return addRegionRunbook{}, err
	}
	plan, err := reconcile.Diff(declared, reconcile.State{})
	if err != nil {
		return addRegionRunbook{}, err
	}
	var actions []reconcile.Action
	for _, action := range plan.Actions {
		if action.Ref.Region == region.Code {
			actions = append(actions, action)
		}
	}
	if len(actions) == 0 {
		return addRegionRunbook{}, errors.New("add-region: declared estate has no resources for region " + region.Code)
	}
	var litestream []estate.Bucket
	for _, bucket := range region.Buckets {
		if bucket.Purpose == addRegionLitestreamPurpose {
			litestream = append(litestream, bucket)
		}
	}
	book := addRegionRunbook{
		Command:       "add-region",
		Region:        region.Code,
		OCIRegion:     region.OCIName,
		EstateVersion: estate.SchemaVersion,
		Stages:        append([]string(nil), addRegionStages...),
		Members: addRegionMembers{
			Count:         region.Members.Count,
			PrimaryShape:  region.Members.PrimaryShape,
			FallbackShape: region.Members.FallbackShape,
			OCPUs:         region.Members.OCPUs,
			MemoryGiB:     region.Members.MemoryGiB,
			BootVolumeGiB: region.Members.BootVolumeGiB,
			DataVolumeGiB: region.Members.DataVolumeGiB,
		},
		Control:           addRegionControl{Mode: "co-hosted", Replicas: region.Members.ControlReplicas},
		ObjectStorage:     append([]estate.Bucket(nil), region.Buckets...),
		LitestreamTargets: litestream,
		Routes:            addRegionRoutesFor(spec, region.Code),
		Probes:            addRegionProbesFor(spec, region),
		Actions:           actions,
	}
	return book, nil
}

// addRegionRoutesFor collects the edge state that serves one region: the
// region's pinned API record plus the shared first-contact and reactive
// entry points, and every declared Worker route.
func addRegionRoutesFor(spec estate.Spec, code string) addRegionRoutes {
	zone := spec.Cloudflare.Zone
	var dns []estate.DNSRecord
	for _, record := range spec.Cloudflare.DNSRecords {
		if record.Name == "api."+zone || record.Name == "sync.api."+zone || record.Name == code+".api."+zone {
			dns = append(dns, record)
		}
	}
	return addRegionRoutes{
		DNSRecords:   dns,
		WorkerRoutes: append([]estate.WorkerRoute(nil), spec.Cloudflare.WorkerRoutes...),
	}
}

// addRegionProbesFor collects what proves one region serves: its KV health
// and placement entries, its member certificates, and the placement member
// floor the region must sustain.
func addRegionProbesFor(spec estate.Spec, region estate.Region) addRegionProbes {
	var kv []addRegionProbeKV
	for _, mapping := range spec.Cloudflare.KVMaps {
		for _, entry := range mapping.Entries {
			if entry.Key == "regions/"+region.Code || entry.Key == "placement/control" {
				kv = append(kv, addRegionProbeKV{Map: mapping.Name, Key: entry.Key, Value: entry.Value})
			}
		}
	}
	return addRegionProbes{
		KV:           kv,
		Certificates: append([]estate.Certificate(nil), region.Certificates...),
		MemberFloor:  provider.PlacementMinimumMemberHosts,
	}
}
