package ocicost

import (
	"regexp"
	"slices"
	"strings"
	"time"
)

// Resource is one OCI resource a tag pass may stamp.
type Resource struct {
	ID          string
	Type        string // Resource Search type, e.g. "Instance", "BootVolume"
	Name        string
	Compartment string
	Created     time.Time
	Tags        map[string]string // freeform
}

// TaggedTypes are the billable resource types a pass stamps.
var TaggedTypes = []string{"Instance", "BootVolume", "Volume", "BootVolumeBackup", "VolumeBackup", "Image", "Bucket", "LoadBalancer"}

// Stamp is one resource's missing or wrong cost tags.
type Stamp struct {
	Resource Resource
	Tags     map[string]string // exactly RegionTag and ComponentTag
}

const (
	drSourceTag = "terrascale-dr-source"
	resourceTag = "terrascale-resource"
	roleTag     = "ts-role"
	appTag      = "terrascale-app"
	poolTag     = "ts-pool"
	// minTagAge keeps a pass away from resources still in their create flow,
	// whose ETag their creator may be holding.
	minTagAge = time.Hour
)

var controllerName = regexp.MustCompile(`^ts-[a-z]+-[0-9]+($|-| )`)

// Component infers a resource's component from the marks it already has,
// or "" when none fits; the pass never guesses.
func Component(cell string, r Resource) string {
	if component := r.Tags[ComponentTag]; slices.Contains(Components, component) {
		return component
	}
	if _, ok := r.Tags[drSourceTag]; ok {
		return "disaster-recovery"
	}
	switch mark := r.Tags[resourceTag]; {
	case strings.HasPrefix(mark, "member-") || mark == "terrabase-host":
		return "terrabase"
	case mark == "managed-volume":
		return "apps"
	}
	if r.Tags[roleTag] == "db" {
		return "terrabase"
	}
	if r.Tags[appTag] != "" {
		return "apps"
	}
	if r.Tags[poolTag] != "" {
		return "node-pool"
	}
	switch r.Type {
	case "Instance", "BootVolume", "Volume", "BootVolumeBackup", "VolumeBackup":
		name := strings.TrimSuffix(r.Name, " (Boot Volume)")
		switch {
		case strings.Contains(name, "-ctl-") || controllerName.MatchString(name):
			return "controller"
		case strings.Contains(name, "-db-") || strings.HasPrefix(name, "ts-member-data-backup-"):
			return "terrabase"
		case strings.Contains(name, "-pool-"):
			return "node-pool"
		}
	case "Bucket":
		if !strings.HasPrefix(r.Name, cell+"-") {
			return "storage"
		}
		switch {
		case strings.HasSuffix(r.Name, "-backup"):
			return "terrabase"
		case strings.HasSuffix(r.Name, "-head"):
			return "releases"
		case strings.HasSuffix(r.Name, "-material") || strings.HasSuffix(r.Name, "-ledger"):
			return "controller"
		}
		return "storage"
	case "Image":
		return "images"
	case "LoadBalancer":
		return "network"
	}
	return ""
}

// PlanTags returns the stamps the cell's resources need at now, and the
// resources no rule fits.
func PlanTags(cell string, resources []Resource, now time.Time) (stamps []Stamp, untagged []Resource) {
	for _, r := range resources {
		if !slices.Contains(TaggedTypes, r.Type) || !r.Created.IsZero() && now.Sub(r.Created) < minTagAge {
			continue
		}
		component := Component(cell, r)
		if component == "" {
			untagged = append(untagged, r)
			continue
		}
		region := strings.ToUpper(cell)
		if r.Tags[RegionTag] == region && r.Tags[ComponentTag] == component {
			continue
		}
		stamps = append(stamps, Stamp{Resource: r, Tags: map[string]string{RegionTag: region, ComponentTag: component}})
	}
	return stamps, untagged
}
