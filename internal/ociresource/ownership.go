package ociresource

import (
	"errors"
	"strconv"
)

// TagMode is retained for source compatibility while callers remove the
// former selector. Production ownership uses freeform tags exclusively.
type TagMode string

const TagModeFreeform TagMode = "freeform"

const (
	managedByValue     = "ts-orchestrator"
	freeformManagedBy  = "terrascale-managed-by"
	freeformOwner      = "terrascale-owner"
	freeformResource   = "terrascale-resource-key"
	freeformGeneration = "terrascale-generation"
	freeformSpecDigest = "terrascale-spec-digest"
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
	if o.Mode != "" && o.Mode != TagModeFreeform || o.Namespace != "" {
		return errors.New("OCI ownership uses freeform tags; alternate tag configuration is retired")
	}
	return nil
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
	if o.Validate() != nil {
		return Tags{}
	}
	return Tags{Freeform: values}
}

// Owns reports whether tags prove this controller owns key. Generation and
// spec digest are not part of the proof: they change when the spec changes
// and are restamped by Apply.
func (o Ownership) Owns(key Key, tags Tags) bool {
	if o.Validate() != nil {
		return false
	}
	return tags.Freeform[freeformManagedBy] == managedByValue && tags.Freeform[freeformOwner] == o.Owner &&
		tags.Freeform[freeformResource] == key.String()
}

// Claimed reports whether tags carry any part of an ownership claim, this
// controller's or another's, in the production ownership tags. A tool that
// stamps ownership onto an existing resource refuses a claimed one it does
// not already own.
func (o Ownership) Claimed(tags Tags) bool {
	if o.Validate() != nil {
		return true
	}
	return tags.Freeform[freeformManagedBy] != "" || tags.Freeform[freeformOwner] != "" || tags.Freeform[freeformResource] != ""
}

// Stale reports whether owned tags lag the desired generation or digest.
func (o Ownership) Stale(tags Tags, generation uint64, specDigest string) bool {
	want := strconv.FormatUint(generation, 10)
	if o.Validate() != nil {
		return true
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
