// Package bucket reconciles the versioning and retention rules of one owned
// OCI Object Storage bucket.
//
// The bucket must already carry the controller's ownership tags for the
// desired key; otherwise it is foreign and nothing is changed. The
// reconciler never creates or deletes buckets or objects. Retention rules it
// manages carry a display-name marker; rules created by other tools are left
// alone. It never creates a locked (time-bound, irreversible) rule and never
// tries to change one: a locked managed rule that differs from the spec is
// reported and the record fails until an operator resolves it. A tombstone
// relinquishes management without touching the bucket, so data protection
// is never removed by a deletion.
package bucket

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
)

// Kind is the desired-state kind for bucket data-protection settings.
const Kind = "bucket-protection"

const (
	VersioningEnabled   = "Enabled"
	VersioningSuspended = "Suspended"
	// VersioningDisabled is reported by OCI for a bucket that never had
	// versioning; it satisfies a Suspended spec and cannot be requested.
	VersioningDisabled = "Disabled"

	UnitDays  = "DAYS"
	UnitYears = "YEARS"

	maxRetentionRules = 16
	maxDays           = 36500
	maxYears          = 100
)

var (
	namespacePattern = regexp.MustCompile(`^[a-z0-9]{1,64}$`)
	bucketPattern    = regexp.MustCompile(`^[A-Za-z0-9._-]{1,256}$`)
	ruleNamePattern  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$`)
)

// Retention is one desired retention rule. Exactly one of Days and Years is
// set. Rules are never locked by the reconciler.
type Retention struct {
	Name  string `json:"name"`
	Days  int    `json:"days,omitempty"`
	Years int    `json:"years,omitempty"`
}

func (r Retention) duration() (int64, string) {
	if r.Years > 0 {
		return int64(r.Years), UnitYears
	}
	return int64(r.Days), UnitDays
}

func (r Retention) validate() error {
	if !ruleNamePattern.MatchString(r.Name) {
		return fmt.Errorf("retention rule name %q is invalid", r.Name)
	}
	switch {
	case r.Days > 0 && r.Years == 0 && r.Days <= maxDays:
	case r.Years > 0 && r.Days == 0 && r.Years <= maxYears:
	default:
		return fmt.Errorf("retention rule %q needs exactly one bounded duration in days or years", r.Name)
	}
	return nil
}

// Spec is the desired data protection of one bucket.
type Spec struct {
	Namespace string `json:"namespace"`
	Bucket    string `json:"bucket"`
	// Versioning is Enabled, Suspended, or empty to leave it unmanaged.
	Versioning string      `json:"versioning,omitempty"`
	Retention  []Retention `json:"retention,omitempty"`
}

// Validate rejects malformed names, durations and combinations OCI refuses.
func (s Spec) Validate() error {
	if !namespacePattern.MatchString(s.Namespace) || !bucketPattern.MatchString(s.Bucket) {
		return errors.New("bucket spec requires an Object Storage namespace and bucket name")
	}
	switch s.Versioning {
	case "", VersioningEnabled, VersioningSuspended:
	default:
		return fmt.Errorf("bucket versioning %q is unsupported", s.Versioning)
	}
	if len(s.Retention) > maxRetentionRules {
		return fmt.Errorf("bucket spec has more than %d retention rules", maxRetentionRules)
	}
	if s.Versioning == VersioningEnabled && len(s.Retention) > 0 {
		// Object Storage refuses retention rules on a versioned bucket.
		return errors.New("bucket spec cannot combine versioning with retention rules")
	}
	names := map[string]bool{}
	for _, rule := range s.Retention {
		if err := rule.validate(); err != nil {
			return err
		}
		if names[rule.Name] {
			return fmt.Errorf("bucket spec repeats retention rule %q", rule.Name)
		}
		names[rule.Name] = true
	}
	return nil
}

// Bucket is an observed bucket.
type Bucket struct {
	Namespace, Name string
	ETag            string
	Versioning      string
	Tags            ociresource.Tags
}

// Rule is an observed retention rule.
type Rule struct {
	ID          string
	DisplayName string
	ETag        string
	Amount      int64
	Unit        string
	// Locked is set once the rule's lock time is set; OCI then refuses to
	// shorten or delete it after that time.
	Locked bool
}

// Observed is the bucket and its retention rules.
type Observed struct {
	Bucket Bucket
	Rules  []Rule
}

// API is the narrow OCI seam.
type API interface {
	GetBucket(ctx context.Context, namespace, bucket string) (Bucket, error)
	ListRetentionRules(ctx context.Context, namespace, bucket string) ([]Rule, error)
	// UpdateBucket sets versioning (when not empty) and tags under If-Match.
	UpdateBucket(ctx context.Context, namespace, bucket, etag, versioning string, tags ociresource.Tags) error
	CreateRetentionRule(ctx context.Context, namespace, bucket, displayName string, amount int64, unit string) error
	UpdateRetentionRule(ctx context.Context, namespace, bucket, id, etag string, amount int64, unit string) error
	DeleteRetentionRule(ctx context.Context, namespace, bucket, id, etag string) error
}

// Reconciler is the ociresource.Resource for bucket data protection.
type Reconciler struct{ API API }

var _ ociresource.Resource[Spec, Observed] = Reconciler{}

func (Reconciler) Kind() string { return Kind }

// marker prefixes the display name of every retention rule the reconciler
// manages for key. Key names and rule names never contain "/", so the
// marker of one key can never match a rule of another key.
func marker(key ociresource.Key) string { return "terrascale/" + key.Name + "/" }

// managedName reports whether displayName is exactly marker+<rule name>.
func managedName(key ociresource.Key, displayName string) bool {
	name, ok := strings.CutPrefix(displayName, marker(key))
	return ok && ruleNamePattern.MatchString(name)
}

func (r Reconciler) Observe(ctx context.Context, target ociresource.Target[Spec]) (Observed, bool, error) {
	if err := target.Spec.Validate(); err != nil {
		return Observed{}, false, err
	}
	if target.Deleting {
		// Deletion relinquishes management and never removes protection.
		return Observed{}, false, nil
	}
	observed, err := r.observe(ctx, target)
	if err != nil {
		return Observed{}, false, err
	}
	return observed, true, nil
}

func (r Reconciler) observe(ctx context.Context, target ociresource.Target[Spec]) (Observed, error) {
	bucket, err := r.API.GetBucket(ctx, target.Spec.Namespace, target.Spec.Bucket)
	if err != nil {
		return Observed{}, err
	}
	if bucket.Namespace != target.Spec.Namespace || bucket.Name != target.Spec.Bucket ||
		!target.Ownership.Owns(target.Key, bucket.Tags) {
		return Observed{}, ociresource.ErrForeign
	}
	rules, err := r.API.ListRetentionRules(ctx, target.Spec.Namespace, target.Spec.Bucket)
	if err != nil {
		return Observed{}, err
	}
	return Observed{Bucket: bucket, Rules: rules}, nil
}

type changes struct {
	versioning bool
	create     []Retention
	update     []struct {
		rule   Rule
		wanted Retention
	}
	remove  []Rule
	blocked []string
}

func versioningInSync(want, have string) bool {
	return want == "" || want == have || want == VersioningSuspended && have == VersioningDisabled
}

func diff(target ociresource.Target[Spec], observed Observed) changes {
	var out changes
	out.versioning = !versioningInSync(target.Spec.Versioning, observed.Bucket.Versioning)
	prefix := marker(target.Key)
	managed := map[string]Rule{}
	for _, rule := range observed.Rules {
		if !managedName(target.Key, rule.DisplayName) {
			if out.versioning && target.Spec.Versioning == VersioningEnabled {
				// OCI refuses versioning while any retention rule exists;
				// a rule this reconciler does not own blocks the switch.
				out.blocked = append(out.blocked, rule.DisplayName+" (unmanaged; blocks versioning)")
			}
			continue
		}
		if _, duplicate := managed[rule.DisplayName]; duplicate {
			out.remove = append(out.remove, rule)
			continue
		}
		managed[rule.DisplayName] = rule
	}
	for _, wanted := range target.Spec.Retention {
		name := prefix + wanted.Name
		rule, ok := managed[name]
		delete(managed, name)
		amount, unit := wanted.duration()
		switch {
		case !ok:
			out.create = append(out.create, wanted)
		case rule.Amount == amount && rule.Unit == unit:
		case rule.Locked:
			out.blocked = append(out.blocked, rule.DisplayName)
		default:
			out.update = append(out.update, struct {
				rule   Rule
				wanted Retention
			}{rule, wanted})
		}
	}
	for _, rule := range managed {
		out.remove = append(out.remove, rule)
	}
	slices.SortFunc(out.remove, func(a, b Rule) int { return strings.Compare(a.ID, b.ID) })
	for _, rule := range out.remove {
		if rule.Locked {
			out.blocked = append(out.blocked, rule.DisplayName)
		}
	}
	return out
}

func (Reconciler) Diff(target ociresource.Target[Spec], observed Observed, found bool) ociresource.Plan {
	var plan ociresource.Plan
	if !found {
		plan.Add("blocked", "bucket %s/%s is not visible", target.Spec.Namespace, target.Spec.Bucket)
		return plan
	}
	c := diff(target, observed)
	if c.versioning {
		plan.Add("versioning", "%s -> %s", observed.Bucket.Versioning, target.Spec.Versioning)
	}
	for _, rule := range c.create {
		amount, unit := rule.duration()
		plan.Add("add-retention", "%s %d %s", rule.Name, amount, unit)
	}
	for _, change := range c.update {
		amount, unit := change.wanted.duration()
		plan.Add("update-retention", "%s %d %s -> %d %s", change.wanted.Name, change.rule.Amount, change.rule.Unit, amount, unit)
	}
	for _, rule := range c.remove {
		plan.Add("remove-retention", "%s", rule.DisplayName)
	}
	for _, name := range c.blocked {
		plan.Add("blocked", "retention rule %s cannot be changed", name)
	}
	if target.Ownership.Stale(observed.Bucket.Tags, target.Generation, target.SpecDigest) {
		plan.Add("tag", "restamp ownership generation %d", target.Generation)
	}
	return plan
}

// Apply removes unwanted managed rules first, then updates versioning and
// ownership, then creates and updates rules, so turning versioning on and
// retention off (or the reverse) never trips OCI's mutual exclusion.
func (r Reconciler) Apply(ctx context.Context, target ociresource.Target[Spec], observed Observed, found bool, _ ociresource.Plan) error {
	if !found {
		return fmt.Errorf("bucket %s/%s is not visible; the reconciler never creates buckets", target.Spec.Namespace, target.Spec.Bucket)
	}
	c := diff(target, observed)
	if len(c.blocked) > 0 {
		return fmt.Errorf("bucket retention rules %s are locked or block versioning; nothing was changed", strings.Join(c.blocked, ", "))
	}
	spec := target.Spec
	for _, rule := range c.remove {
		if err := target.Fence(ctx); err != nil {
			return err
		}
		if err := r.API.DeleteRetentionRule(ctx, spec.Namespace, spec.Bucket, rule.ID, rule.ETag); err != nil {
			return fmt.Errorf("delete retention rule: %w", err)
		}
	}
	bucket := observed.Bucket
	stale := target.Ownership.Stale(bucket.Tags, target.Generation, target.SpecDigest)
	if c.versioning || stale {
		if len(c.remove) > 0 {
			// Re-read for a fresh ETag, and only while still owned.
			fresh, err := r.observe(ctx, target)
			if err != nil {
				return fmt.Errorf("re-read bucket before update: %w", err)
			}
			bucket = fresh.Bucket
		}
		versioning := ""
		if c.versioning {
			versioning = spec.Versioning
		}
		tags := bucket.Tags.Merge(target.Ownership.Stamp(target.Key, target.Generation, target.SpecDigest))
		if err := target.Fence(ctx); err != nil {
			return err
		}
		if err := r.API.UpdateBucket(ctx, spec.Namespace, spec.Bucket, bucket.ETag, versioning, tags); err != nil {
			return fmt.Errorf("update bucket: %w", err)
		}
	}
	for _, change := range c.update {
		amount, unit := change.wanted.duration()
		if err := target.Fence(ctx); err != nil {
			return err
		}
		if err := r.API.UpdateRetentionRule(ctx, spec.Namespace, spec.Bucket, change.rule.ID, change.rule.ETag, amount, unit); err != nil {
			return fmt.Errorf("update retention rule: %w", err)
		}
	}
	for _, rule := range c.create {
		amount, unit := rule.duration()
		if err := target.Fence(ctx); err != nil {
			return err
		}
		if err := r.API.CreateRetentionRule(ctx, spec.Namespace, spec.Bucket, marker(target.Key)+rule.Name, amount, unit); err != nil {
			return fmt.Errorf("create retention rule: %w", err)
		}
	}
	return nil
}

// Delete is never reached: Observe reports a tombstoned bucket as not found.
func (Reconciler) Delete(context.Context, ociresource.Target[Spec], Observed) error { return nil }
