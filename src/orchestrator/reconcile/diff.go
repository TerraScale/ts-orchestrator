package reconcile

import (
	"errors"
	"sort"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

// ActionKind names one planned transition.
type ActionKind string

const (
	// ActionCreate: the resource is declared but not observed.
	ActionCreate ActionKind = "create"
	// ActionUpdate: the resource is observed with different attributes.
	ActionUpdate ActionKind = "update"
	// ActionDelete: the resource is observed but not declared.
	ActionDelete ActionKind = "delete"
)

// Change is one attribute difference of an update.
type Change struct {
	Name     string `json:"name"`
	Declared string `json:"declared"`
	Observed string `json:"observed"`
}

// Action is one planned transition of one resource. Create actions carry the
// declared attributes; update actions carry the changed attributes; delete
// actions carry the observed attributes.
type Action struct {
	Kind       ActionKind         `json:"kind"`
	Ref        estate.ResourceRef `json:"ref"`
	Attributes []Attribute        `json:"attributes,omitempty"`
	Changes    []Change           `json:"changes,omitempty"`
	// Repair is set when a provider reported an existing resource as failed.
	// It lets adapters run their self-healing path even when attributes already
	// match the declaration.
	Repair    bool           `json:"repair,omitempty"`
	Ownership OwnershipProof `json:"ownership,omitempty"`
}

// Plan is the deterministic set of transitions derived from one observation.
type Plan struct {
	Actions []Action `json:"actions"`
}

// Empty reports whether the plan would change nothing.
func (p Plan) Empty() bool { return len(p.Actions) == 0 }

// For returns the slice of the plan owned by the given resource kinds, in
// plan order. Provider adapters apply exactly this filtered view.
func (p Plan) For(kinds ...estate.ResourceKind) Plan {
	owned := make(map[estate.ResourceKind]struct{}, len(kinds))
	for _, kind := range kinds {
		owned[kind] = struct{}{}
	}
	var filtered Plan
	for _, action := range p.Actions {
		if _, ok := owned[action.Ref.Kind]; ok {
			filtered.Actions = append(filtered.Actions, action)
		}
	}
	return filtered
}

// Diff derives the plan that drives observed to declared. Only the given
// kinds are diffed; kinds without an owner in this loop instance are not this
// loop's business. An empty kind set means every declared kind.
func Diff(declared, observed State, kinds ...estate.ResourceKind) (Plan, error) {
	scope := func(kind estate.ResourceKind) bool {
		if len(kinds) == 0 {
			return true
		}
		for _, candidate := range kinds {
			if candidate == kind {
				return true
			}
		}
		return false
	}
	indexed, err := observed.ByRef()
	if err != nil {
		return Plan{}, err
	}
	var plan Plan
	for _, resource := range declared.Resources {
		if !scope(resource.Ref.Kind) {
			continue
		}
		key := RefKey(resource.Ref)
		current, exists := indexed[key]
		if !exists {
			plan.Actions = append(plan.Actions, Action{
				Kind:       ActionCreate,
				Ref:        resource.Ref,
				Attributes: normalizeAttributes(resource.Attributes),
			})
			continue
		}
		delete(indexed, key)
		switch current.Status {
		case ResourceIndeterminate:
			// A provider work request or read whose outcome cannot be proved is
			// not safe to mutate. Return the error after collecting deterministic
			// drift for the other resources; callers must not apply this plan.
			continue
		case ResourceCreating:
			// Do not submit a duplicate create while the provider is converging.
			continue
		}
		if current.Status == ResourceFailed && sameAttributes(resource.Attributes, current.Attributes) {
			plan.Actions = append(plan.Actions, Action{Kind: ActionUpdate, Ref: resource.Ref, Attributes: normalizeAttributes(resource.Attributes), Repair: true, Ownership: current.Ownership})
			continue
		}
		if changes := attributeChanges(resource.Attributes, current.Attributes); len(changes) > 0 {
			plan.Actions = append(plan.Actions, Action{
				Kind:       ActionUpdate,
				Ref:        resource.Ref,
				Changes:    changes,
				Attributes: normalizeAttributes(resource.Attributes),
				Ownership:  current.Ownership,
			})
		}
	}
	// Everything observed but undeclared is drift to remove.
	var extras []Resource
	for _, resource := range indexed {
		if scope(resource.Ref.Kind) {
			extras = append(extras, resource)
		}
	}
	sort.Slice(extras, func(i, j int) bool { return RefKey(extras[i].Ref) < RefKey(extras[j].Ref) })
	for _, resource := range extras {
		if resource.Status == ResourceIndeterminate {
			continue
		}
		plan.Actions = append(plan.Actions, Action{
			Kind:       ActionDelete,
			Ref:        resource.Ref,
			Attributes: normalizeAttributes(resource.Attributes),
			Ownership:  resource.Ownership,
		})
	}
	sort.SliceStable(plan.Actions, func(i, j int) bool { return actionLess(plan.Actions[i], plan.Actions[j]) })
	var unsafe []error
	for _, resource := range observed.Resources {
		if !scope(resource.Ref.Kind) || resource.Status != ResourceIndeterminate {
			continue
		}
		unsafe = append(unsafe, &IndeterminateError{Ref: resource.Ref})
	}
	if len(unsafe) > 0 {
		return plan, errors.Join(unsafe...)
	}
	return plan, nil
}

// IndeterminateError marks a provider observation that must not be acted on.
// It is exported so callers can distinguish an unsafe plan from a partial
// provider outage and continue repairing healthy provider domains.
type IndeterminateError struct{ Ref estate.ResourceRef }

func (e *IndeterminateError) Error() string {
	return "reconcile: indeterminate resource " + RefKey(e.Ref)
}

// actionLess gives dependency-aware, deterministic ordering. Deletes run in
// reverse dependency order so references (routes, subnets, etc.) disappear
// before their parents. Unknown kinds retain a stable lexical order.
func actionLess(left, right Action) bool {
	leftPhase, rightPhase := actionPhase(left.Kind), actionPhase(right.Kind)
	if leftPhase != rightPhase {
		return leftPhase < rightPhase
	}
	leftRank, rightRank := kindRank(left.Ref.Kind), kindRank(right.Ref.Kind)
	if left.Kind == ActionDelete {
		if leftRank != rightRank {
			return leftRank > rightRank
		}
	} else if leftRank != rightRank {
		return leftRank < rightRank
	}
	return RefKey(left.Ref) < RefKey(right.Ref)
}

func actionPhase(kind ActionKind) int {
	switch kind {
	case ActionCreate:
		return 0
	case ActionUpdate:
		return 1
	case ActionDelete:
		return 2
	default:
		return 3
	}
}

func kindRank(kind estate.ResourceKind) int {
	for i, candidate := range []estate.ResourceKind{
		estate.ResourceNetwork, estate.ResourceSubnet, estate.ResourceNSG,
		estate.ResourceBucket, estate.ResourceVaultKey, estate.ResourceCertificate,
		estate.ResourceCompute, estate.ResourceDNS, estate.ResourceCacheRule,
		estate.ResourceSnippetRule, estate.ResourceWorkerRoute, estate.ResourceKVMap,
		estate.ResourceWAFRule, estate.ResourceRateRule, estate.ResourceCapabilityKey,
	} {
		if candidate == kind {
			return i
		}
	}
	return 1000
}

// attributeChanges compares two attribute multisets and returns every
// differing attribute as a change against the declared value.
func attributeChanges(declared, observed []Attribute) []Change {
	declaredIndex := indexAttributes(declared)
	observedIndex := indexAttributes(observed)
	var changes []Change
	names := make(map[string]struct{}, len(declaredIndex)+len(observedIndex))
	for name := range declaredIndex {
		names[name] = struct{}{}
	}
	for name := range observedIndex {
		names[name] = struct{}{}
	}
	sorted := make([]string, 0, len(names))
	for name := range names {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)
	for _, name := range sorted {
		want := declaredIndex[name]
		have := observedIndex[name]
		if sameMultiset(want, have) {
			continue
		}
		changes = append(changes, Change{Name: name, Declared: multisetValue(want), Observed: multisetValue(have)})
	}
	return changes
}

func indexAttributes(attributes []Attribute) map[string][]string {
	indexed := make(map[string][]string, len(attributes))
	for _, attribute := range attributes {
		indexed[attribute.Name] = append(indexed[attribute.Name], attribute.Value)
	}
	for name := range indexed {
		values := indexed[name]
		sort.Strings(values)
	}
	return indexed
}

func sameMultiset(declared, observed []string) bool {
	if len(declared) != len(observed) {
		return false
	}
	for i := range declared {
		if declared[i] != observed[i] {
			return false
		}
	}
	return true
}

func multisetValue(values []string) string {
	value := ""
	for i, item := range values {
		if i > 0 {
			value += ","
		}
		value += item
	}
	return value
}
