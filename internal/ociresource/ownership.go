package ociresource

import (
	"errors"
	"fmt"
	"strconv"
)

// TagMode selects where ownership tags live on OCI resources.
type TagMode string

const (
	// TagModeFreeform keeps ownership in terrascale-* freeform tags, matching
	// the member-host fleet. It is the default because it needs no tenancy
	// setup.
	TagModeFreeform TagMode = "freeform"
	// TagModeDefined keeps ownership in a defined-tag namespace. Only
	// principals granted "use tag-namespaces" on that namespace can write
	// it, so ownership cannot be forged by anyone with generic tag rights.
	// The namespace and its keys must exist before this mode is enabled.
	TagModeDefined TagMode = "defined"
)

const (
	// DefaultTagNamespace is the defined-tag namespace for TagModeDefined.
	DefaultTagNamespace = "terrascale"
	managedByValue      = "ts-orchestrator"

	freeformManagedBy  = "terrascale-managed-by"
	freeformOwner      = "terrascale-owner"
	freeformResource   = "terrascale-resource-key"
	freeformGeneration = "terrascale-generation"
	freeformSpecDigest = "terrascale-spec-digest"

	definedManagedBy  = "managed-by"
	definedOwner      = "owner"
	definedResource   = "resource-key"
	definedGeneration = "generation"
	definedSpecDigest = "spec-digest"
)

// Ownership is the controller identity stamped on, and required from, every
// resource this framework manages.
type Ownership struct {
	Mode      TagMode
	Namespace string
	Owner     string
}

// Validate rejects an empty owner or an unknown tag mode.
func (o Ownership) Validate() error {
	if !tokenPattern.MatchString(o.Owner) {
		return errors.New("OCI resource ownership requires a token owner")
	}
	switch o.Mode {
	case TagModeFreeform:
	case TagModeDefined:
		if !tokenPattern.MatchString(o.namespace()) {
			return errors.New("OCI resource ownership defined-tag namespace is invalid")
		}
	default:
		return fmt.Errorf("OCI resource ownership tag mode %q is unsupported", o.Mode)
	}
	return nil
}

func (o Ownership) namespace() string {
	if o.Namespace == "" {
		return DefaultTagNamespace
	}
	return o.Namespace
}

// Tags is a resource's freeform and defined tags.
type Tags struct {
	Freeform map[string]string
	Defined  map[string]map[string]any
}

// Stamp returns the ownership tags for key at generation and spec digest.
func (o Ownership) Stamp(key Key, generation uint64, specDigest string) Tags {
	values := map[string]string{
		freeformManagedBy: managedByValue, freeformOwner: o.Owner, freeformResource: key.String(),
		freeformGeneration: strconv.FormatUint(generation, 10), freeformSpecDigest: specDigest,
	}
	if o.Mode != TagModeDefined {
		return Tags{Freeform: values}
	}
	return Tags{Defined: map[string]map[string]any{o.namespace(): {
		definedManagedBy: managedByValue, definedOwner: o.Owner, definedResource: key.String(),
		definedGeneration: strconv.FormatUint(generation, 10), definedSpecDigest: specDigest,
	}}}
}

// Owns reports whether tags prove this controller owns key. Generation and
// spec digest are not part of the proof: they change when the spec changes
// and are restamped by Apply.
func (o Ownership) Owns(key Key, tags Tags) bool {
	if o.Mode == TagModeDefined {
		namespace := tags.Defined[o.namespace()]
		return fmt.Sprint(namespace[definedManagedBy]) == managedByValue &&
			fmt.Sprint(namespace[definedOwner]) == o.Owner && fmt.Sprint(namespace[definedResource]) == key.String()
	}
	return tags.Freeform[freeformManagedBy] == managedByValue && tags.Freeform[freeformOwner] == o.Owner &&
		tags.Freeform[freeformResource] == key.String()
}

// Stale reports whether owned tags lag the desired generation or digest.
func (o Ownership) Stale(tags Tags, generation uint64, specDigest string) bool {
	want := strconv.FormatUint(generation, 10)
	if o.Mode == TagModeDefined {
		namespace := tags.Defined[o.namespace()]
		return fmt.Sprint(namespace[definedGeneration]) != want || fmt.Sprint(namespace[definedSpecDigest]) != specDigest
	}
	return tags.Freeform[freeformGeneration] != want || tags.Freeform[freeformSpecDigest] != specDigest
}

// Merge overlays ownership tags on existing tags without dropping tags owned
// by other tools.
func (t Tags) Merge(ownership Tags) Tags {
	merged := Tags{Freeform: map[string]string{}, Defined: map[string]map[string]any{}}
	for key, value := range t.Freeform {
		merged.Freeform[key] = value
	}
	for key, value := range ownership.Freeform {
		merged.Freeform[key] = value
	}
	for namespace, values := range t.Defined {
		merged.Defined[namespace] = map[string]any{}
		for key, value := range values {
			merged.Defined[namespace][key] = value
		}
	}
	for namespace, values := range ownership.Defined {
		if merged.Defined[namespace] == nil {
			merged.Defined[namespace] = map[string]any{}
		}
		for key, value := range values {
			merged.Defined[namespace][key] = value
		}
	}
	return merged
}
