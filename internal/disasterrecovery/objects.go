package disasterrecovery

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	"golang.org/x/sync/errgroup"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/command"
)

type objectClient interface {
	GetBucket(context.Context, objectstorage.GetBucketRequest) (objectstorage.GetBucketResponse, error)
	CreateBucket(context.Context, objectstorage.CreateBucketRequest) (objectstorage.CreateBucketResponse, error)
	ListRetentionRules(context.Context, objectstorage.ListRetentionRulesRequest) (objectstorage.ListRetentionRulesResponse, error)
	ListReplicationPolicies(context.Context, objectstorage.ListReplicationPoliciesRequest) (objectstorage.ListReplicationPoliciesResponse, error)
	CreateReplicationPolicy(context.Context, objectstorage.CreateReplicationPolicyRequest) (objectstorage.CreateReplicationPolicyResponse, error)
	ListObjects(context.Context, objectstorage.ListObjectsRequest) (objectstorage.ListObjectsResponse, error)
	GetObject(context.Context, objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error)
	CopyObject(context.Context, objectstorage.CopyObjectRequest) (objectstorage.CopyObjectResponse, error)
	GetWorkRequest(context.Context, objectstorage.GetWorkRequestRequest) (objectstorage.GetWorkRequestResponse, error)
}

type serviceError interface {
	error
	common.ServiceError
}

// CopyReport names the continuous mirror and the writable, versioned backfill.
// OCI does not replicate objects uploaded before a policy was created. Reads
// during recovery must select verified generations across both buckets;
// asynchronous replication means the mirror may contain an older generation.
// Successful create IDs survive later failures so operators can review and pin
// them in config before another run. An unknown create response stays unowned.
type CopyReport struct {
	SourceRegion   string     `json:"source_region"`
	TargetRegion   string     `json:"target_region"`
	SourceBucket   string     `json:"source_bucket"`
	MirrorBucket   string     `json:"mirror_bucket"`
	MirrorBucketID string     `json:"mirror_bucket_id,omitempty"`
	SeedBucket     string     `json:"seed_bucket"`
	SeedBucketID   string     `json:"seed_bucket_id,omitempty"`
	PolicyID       string     `json:"policy_id,omitempty"`
	LastSync       *time.Time `json:"last_sync,omitempty"`
	Seeded         int        `json:"seeded"`
	Mirrored       int        `json:"mirrored"` // Source objects already identical in the mirror.
	Planned        bool       `json:"planned"`
}

type copier struct {
	source, target                                                objectClient
	namespace, sourceRegion, targetRegion, sourceCell, targetCell string
	sourceConfig, targetConfig                                    Region
	apply                                                         bool
	workers                                                       int
	Pause                                                         func(context.Context, time.Duration) error
}

func newCopier(source, target *ociclient.Factory, config Config, sourceCell, targetCell string,
	sourceConfig, targetConfig Region, apply bool,
) (*copier, error) {
	s, err := source.ObjectStorage()
	if err != nil {
		return nil, err
	}
	t, err := target.ObjectStorage()
	if err != nil {
		return nil, err
	}
	return &copier{source: s, target: t, namespace: config.Namespace, sourceRegion: source.Region(),
		targetRegion: target.Region(), sourceCell: sourceCell, targetCell: targetCell,
		sourceConfig: sourceConfig, targetConfig: targetConfig, apply: apply, workers: 16, Pause: command.Pause}, nil
}

func (c *copier) copy(ctx context.Context, role string) (CopyReport, error) {
	r := CopyReport{SourceRegion: c.sourceRegion, TargetRegion: c.targetRegion,
		SourceBucket: c.sourceCell + "-1-" + role,
		MirrorBucket: c.targetCell + "-1-dr-" + c.sourceCell + "-1-" + role,
		SeedBucket:   c.targetCell + "-1-dr-" + c.sourceCell + "-1-" + role + "-seed", Planned: !c.apply}
	r.MirrorBucketID = c.targetConfig.BucketIDs[r.MirrorBucket]
	r.SeedBucketID = c.targetConfig.BucketIDs[r.SeedBucket]
	r.PolicyID = c.sourceConfig.PolicyIDs["TS-641-"+r.SourceBucket]
	source, err := c.source.GetBucket(ctx, objectstorage.GetBucketRequest{NamespaceName: &c.namespace, BucketName: &r.SourceBucket})
	if err != nil {
		return r, fmt.Errorf("inspect source %s: %w", r.SourceBucket, err)
	}
	if !same(source.Name, r.SourceBucket) || !same(source.Namespace, c.namespace) ||
		!same(source.CompartmentId, c.sourceConfig.CompartmentID) || !same(source.KmsKeyId, c.sourceConfig.KeyID) ||
		source.PublicAccessType != objectstorage.BucketPublicAccessTypeNopublicaccess ||
		source.IsReadOnly == nil || *source.IsReadOnly || source.StorageTier != objectstorage.BucketStorageTierStandard {
		return r, fmt.Errorf("source %s differs from the pinned private regional bucket", r.SourceBucket)
	}
	// Inspect every destination and existing policy before creating anything.
	policy, err := c.policy(ctx, r)
	if err != nil {
		return r, err
	}
	destinations := []struct {
		name string
		id   *string
		seed bool
	}{{r.MirrorBucket, &r.MirrorBucketID, false}, {r.SeedBucket, &r.SeedBucketID, true}}
	for _, destination := range destinations {
		if _, err := c.bucket(ctx, destination.name, *destination.id, destination.seed, false); err != nil {
			return r, err
		}
	}
	if !c.apply {
		if policy != nil {
			r.PolicyID = *policy.Id
			if policy.TimeLastSync != nil {
				r.LastSync = &policy.TimeLastSync.Time
			}
			if policy.Status != objectstorage.ReplicationPolicySummaryStatusActive {
				return r, fmt.Errorf("replication %s is %s; check Object Storage service grants", r.PolicyID, policy.Status)
			}
		}
		return r, nil
	}
	for _, destination := range destinations {
		*destination.id, err = c.bucket(ctx, destination.name, *destination.id, destination.seed, true)
		if err != nil {
			return r, err
		}
	}
	if policy == nil {
		// Provisioning the seed can take long enough for the mirror name to
		// be replaced. Revalidate its recorded identity before making it
		// read-only through a name-addressed replication policy.
		if _, err := c.bucket(ctx, r.MirrorBucket, r.MirrorBucketID, false, false); err != nil {
			return r, err
		}
		created, err := c.source.CreateReplicationPolicy(ctx, objectstorage.CreateReplicationPolicyRequest{
			NamespaceName: &c.namespace, BucketName: &r.SourceBucket,
			CreateReplicationPolicyDetails: objectstorage.CreateReplicationPolicyDetails{Name: new("TS-641-" + r.SourceBucket),
				DestinationRegionName: &c.targetRegion, DestinationBucketName: &r.MirrorBucket}})
		if err != nil {
			return r, fmt.Errorf("create replication for %s returned no trusted ID; inspect manually before pinning in config: %w", r.SourceBucket, err)
		}
		if created.Id != nil {
			r.PolicyID = *created.Id
		}
		if !policyIDPattern.MatchString(r.PolicyID) {
			return r, errors.New("create replication returned no valid policy ID; inspect manually before pinning in config")
		}
	}
	if err := c.replicating(ctx, &r); err != nil {
		return r, err
	}
	// Policy creation is another asynchronous boundary. A same-name seed
	// replacement must not receive writes belonging to the recorded OCID.
	if _, err := c.bucket(ctx, r.SeedBucket, r.SeedBucketID, true, false); err != nil {
		return r, err
	}
	// The policy is active before listing. Objects added during this pass go
	// to the mirror, closing the race between inventory and policy creation.
	// ponytail: seed versions are retained without GC until a qualified cold
	// restore defines the baseline/window; add a scoped lifecycle then.
	r.Seeded, r.Mirrored, err = c.seed(ctx, r)
	if err == nil {
		_, err = c.bucket(ctx, r.SeedBucket, r.SeedBucketID, true, false)
	}
	// Skipped objects count only while the policy still feeds the same
	// read-only mirror; a removed policy makes the mirror writable again.
	if err == nil {
		err = c.replicating(ctx, &r)
	}
	return r, err
}

// replicating binds the active policy to the recorded read-only mirror.
func (c *copier) replicating(ctx context.Context, r *CopyReport) error {
	policy, err := c.policy(ctx, *r)
	if err != nil {
		return err
	}
	r.PolicyID = *policy.Id
	if policy.TimeLastSync != nil {
		r.LastSync = &policy.TimeLastSync.Time
	}
	if policy.Status != objectstorage.ReplicationPolicySummaryStatusActive {
		return fmt.Errorf("replication %s is %s; check Object Storage service grants", r.PolicyID, policy.Status)
	}
	mirror, err := c.target.GetBucket(ctx, objectstorage.GetBucketRequest{NamespaceName: &c.namespace, BucketName: &r.MirrorBucket})
	if err != nil || !same(mirror.Id, r.MirrorBucketID) || mirror.IsReadOnly == nil || !*mirror.IsReadOnly {
		return fmt.Errorf("replication destination %s changed identity or is not read-only yet; review and pin report IDs before rerunning: %v", r.MirrorBucket, err)
	}
	return nil
}

func (c *copier) policy(ctx context.Context, r CopyReport) (*objectstorage.ReplicationPolicySummary, error) {
	response, err := c.source.ListReplicationPolicies(ctx, objectstorage.ListReplicationPoliciesRequest{
		NamespaceName: &c.namespace, BucketName: &r.SourceBucket})
	if err != nil {
		return nil, err
	}
	if response.OpcNextPage != nil && *response.OpcNextPage != "" || len(response.Items) > 1 {
		return nil, errors.New("unexpected multiple replication policies")
	}
	if len(response.Items) == 0 {
		if r.PolicyID != "" {
			return nil, fmt.Errorf("pinned replication policy %s is missing; inspect manually", r.PolicyID)
		}
		return nil, nil
	}
	p := response.Items[0]
	if r.PolicyID == "" || !same(p.Id, r.PolicyID) || !same(p.Name, "TS-641-"+r.SourceBucket) ||
		!same(p.DestinationRegionName, c.targetRegion) || !same(p.DestinationBucketName, r.MirrorBucket) {
		return nil, fmt.Errorf("%s has an unowned or different replication policy; inspect manually and pin its reviewed ID in config", r.SourceBucket)
	}
	return &p, nil
}

func (c *copier) bucket(ctx context.Context, name, id string, seed, create bool) (string, error) {
	r, err := c.target.GetBucket(ctx, objectstorage.GetBucketRequest{NamespaceName: &c.namespace, BucketName: &name})
	if err != nil {
		// OCI's ambiguous 404 is never authority to create or adopt a bucket.
		if !ociError(err, http.StatusNotFound, "BucketNotFound") {
			return id, fmt.Errorf("inspect %s: %w", name, err)
		}
		if id != "" {
			return id, fmt.Errorf("pinned bucket %s (%s) is missing; inspect manually", name, id)
		}
		if !create {
			return "", nil
		}
		versioning := objectstorage.CreateBucketDetailsVersioningDisabled
		if seed {
			versioning = objectstorage.CreateBucketDetailsVersioningEnabled
		}
		created, err := c.target.CreateBucket(ctx, objectstorage.CreateBucketRequest{NamespaceName: &c.namespace,
			CreateBucketDetails: objectstorage.CreateBucketDetails{Name: &name, CompartmentId: &c.targetConfig.CompartmentID,
				KmsKeyId: &c.targetConfig.KeyID, PublicAccessType: objectstorage.CreateBucketDetailsPublicAccessTypeNopublicaccess,
				StorageTier: objectstorage.CreateBucketDetailsStorageTierStandard, Versioning: versioning,
				FreeformTags: map[string]string{"terrascale-ticket": "TS-641", "terrascale-dr-source": c.sourceCell + "-1"}}})
		if err != nil {
			return "", fmt.Errorf("create %s returned no trusted ID; inspect manually before pinning in config: %w", name, err)
		}
		if created.Id != nil {
			id = *created.Id
		}
		if !validOCID(id, "bucket", c.targetRegion) {
			return id, fmt.Errorf("create %s returned no valid regional bucket OCID; inspect manually before pinning in config", name)
		}
		return c.bucket(ctx, name, id, seed, false)
	}
	if id == "" || !same(r.Id, id) {
		return id, fmt.Errorf("destination %s is unowned or differs from its pinned bucket OCID; inspect manually and pin its reviewed ID in config", name)
	}
	versioning := objectstorage.BucketVersioningDisabled
	if seed {
		versioning = objectstorage.BucketVersioningEnabled
	}
	if !same(r.Name, name) || !same(r.Namespace, c.namespace) || !same(r.CompartmentId, c.targetConfig.CompartmentID) ||
		!same(r.KmsKeyId, c.targetConfig.KeyID) || r.PublicAccessType != objectstorage.BucketPublicAccessTypeNopublicaccess ||
		r.StorageTier != objectstorage.BucketStorageTierStandard || r.Versioning != versioning ||
		r.FreeformTags["terrascale-ticket"] != "TS-641" || r.FreeformTags["terrascale-dr-source"] != c.sourceCell+"-1" ||
		r.IsReadOnly == nil || seed && *r.IsReadOnly || r.ReplicationEnabled == nil || *r.ReplicationEnabled {
		return id, fmt.Errorf("destination %s has conflicting ownership, encryption or replication settings", name)
	}
	if !seed {
		rules, err := c.target.ListRetentionRules(ctx, objectstorage.ListRetentionRulesRequest{NamespaceName: &c.namespace, BucketName: &name})
		if err != nil {
			return id, err
		}
		if len(rules.Items) != 0 || rules.OpcNextPage != nil && *rules.OpcNextPage != "" {
			return id, fmt.Errorf("replication destination %s cannot have retention rules", name)
		}
	}
	return id, nil
}

// seed copies every current source object that the mirror lacks. Objects
// on one inventory page are copied by bounded workers; a sequential pass
// spends most of its time polling copy work requests.
func (c *copier) seed(ctx context.Context, r CopyReport) (int, int, error) {
	request := objectstorage.ListObjectsRequest{NamespaceName: &c.namespace, BucketName: &r.SourceBucket,
		Fields: new("name,size,md5,etag"), Limit: new(1000)}
	var copied, mirrored atomic.Int64
	counts := func() (int, int) { return int(copied.Load()), int(mirrored.Load()) }
	for {
		response, err := c.source.ListObjects(ctx, request)
		if err != nil {
			s, m := counts()
			return s, m, err
		}
		group, groupCtx := errgroup.WithContext(ctx)
		group.SetLimit(max(c.workers, 1))
		for _, object := range response.Objects {
			group.Go(func() error {
				seededOne, mirroredOne, err := c.seedObject(groupCtx, ctx, r, object)
				if seededOne {
					copied.Add(1)
				}
				if mirroredOne {
					mirrored.Add(1)
				}
				return err
			})
		}
		err = group.Wait()
		s, m := counts()
		if err != nil {
			return s, m, err
		}
		next := response.NextStartWith
		if next == nil || *next == "" {
			return s, m, nil
		}
		if request.Start != nil && *next <= *request.Start {
			return s, m, errors.New("backfill inventory pagination did not advance")
		}
		request.Start = next
	}
}

// seedObject reports whether it verified a new seed copy, or found the
// object already identical in the mirror. Neither is true for an object
// a previous pass already seeded. ctx stops admitting work after a sibling
// fails; a copy already submitted is seen through on drain, because an
// abandoned server-side copy would race a rerun's copy of the same object.
func (c *copier) seedObject(ctx, drain context.Context, r CopyReport, object objectstorage.ObjectSummary) (copied, mirrored bool, err error) {
	if object.Name == nil || *object.Name == "" || object.Etag == nil || *object.Etag == "" || object.Size == nil || *object.Size < 0 {
		return false, false, errors.New("backfill inventory lacks object size or ETag")
	}
	// Replication already holds this version, so the seed covers only what
	// the mirror lacks. Source deletes replicate to the mirror: the source
	// bucket's retention rule, not the seed, protects these objects.
	head, err := c.metadata(ctx, r.MirrorBucket, *object.Name)
	if err == nil {
		matched, err := c.matches(ctx, r, r.MirrorBucket, object, head)
		if err != nil || matched {
			return false, matched, err
		}
	} else if !ociError(err, http.StatusNotFound, "ObjectNotFound") {
		return false, false, err
	}
	head, err = c.metadata(ctx, r.SeedBucket, *object.Name)
	if err == nil {
		matched, err := c.matches(ctx, r, r.SeedBucket, object, head)
		if err != nil || matched {
			return false, false, err
		}
	}
	if err != nil && !ociError(err, http.StatusNotFound, "ObjectNotFound") {
		return false, false, err
	}
	details := objectstorage.CopyObjectDetails{SourceObjectName: object.Name, SourceObjectIfMatchETag: object.Etag,
		DestinationRegion: &c.targetRegion, DestinationNamespace: &c.namespace, DestinationBucket: &r.SeedBucket, DestinationObjectName: object.Name}
	if err != nil {
		details.DestinationObjectIfNoneMatchETag = new("*")
	} else {
		if head.ETag == nil || *head.ETag == "" {
			return false, false, errors.New("backfill destination lacks ETag")
		}
		details.DestinationObjectIfMatchETag = head.ETag
	}
	// Each asynchronous copy addresses a bucket name, so admission
	// must still bind that name to the recorded seed identity.
	if _, err := c.bucket(ctx, r.SeedBucket, r.SeedBucketID, true, false); err != nil {
		return false, false, err
	}
	// Inherit the admitted destination bucket's key. An explicit
	// cross-region KMS header is resolved by the source endpoint and
	// fails with KmsHostNotFound for the destination region's key.
	if err := ctx.Err(); err != nil {
		return false, false, err
	}
	started, err := c.source.CopyObject(drain, objectstorage.CopyObjectRequest{NamespaceName: &c.namespace, BucketName: &r.SourceBucket,
		CopyObjectDetails: details})
	if err != nil {
		return false, false, fmt.Errorf("backfill %s: %w", *object.Name, err)
	}
	if started.OpcWorkRequestId == nil || *started.OpcWorkRequestId == "" {
		return false, false, errors.New("copy returned no work request ID")
	}
	if err := c.waitCopy(drain, *started.OpcWorkRequestId); err != nil {
		return false, false, err
	}
	head, err = c.metadata(drain, r.SeedBucket, *object.Name)
	if err != nil {
		return false, false, fmt.Errorf("backfill %s failed checksum/size readback: %w", *object.Name, err)
	}
	matched, err := c.matches(drain, r, r.SeedBucket, object, head)
	if err != nil {
		return false, false, err
	}
	if !matched {
		return false, false, fmt.Errorf("backfill %s failed checksum/size readback", *object.Name)
	}
	return true, false, nil
}

func (c *copier) matches(ctx context.Context, r CopyReport, bucket string, object objectstorage.ObjectSummary, head objectstorage.GetObjectResponse) (bool, error) {
	if head.ContentLength == nil || *head.ContentLength != *object.Size {
		return false, nil
	}
	// Multipart MD5s describe part boundaries, which a server-side copy may
	// change. Compare actual bytes when ordinary object MD5s are unavailable.
	if object.Md5 != nil && *object.Md5 != "" && !strings.Contains(*object.Md5, "-") &&
		head.ContentMd5 != nil && *head.ContentMd5 != "" && !strings.Contains(*head.ContentMd5, "-") {
		return *object.Md5 == *head.ContentMd5, nil
	}
	if head.ETag == nil || *head.ETag == "" {
		return false, errors.New("backfill destination lacks ETag")
	}
	source, err := c.digest(ctx, c.source, r.SourceBucket, *object.Name, *object.Etag, *object.Size)
	if err != nil {
		return false, err
	}
	target, err := c.digest(ctx, c.target, bucket, *object.Name, *head.ETag, *object.Size)
	return source == target, err
}

func (c *copier) digest(ctx context.Context, client objectClient, bucket, name, etag string, size int64) ([32]byte, error) {
	response, err := client.GetObject(ctx, objectstorage.GetObjectRequest{NamespaceName: &c.namespace, BucketName: &bucket, ObjectName: &name, IfMatch: &etag})
	if err != nil {
		return [32]byte{}, err
	}
	if response.Content == nil {
		return [32]byte{}, errors.New("checksum read returned no body")
	}
	if response.ContentLength == nil || *response.ContentLength != size || !same(response.ETag, etag) {
		return [32]byte{}, errors.Join(errors.New("checksum read changed size or ETag"), response.Content.Close())
	}
	hash := sha256.New()
	read, err := io.Copy(hash, io.LimitReader(response.Content, size))
	var extra [1]byte
	n, extraErr := response.Content.Read(extra[:])
	err = errors.Join(err, response.Content.Close())
	if err != nil || read != size || n != 0 || !errors.Is(extraErr, io.EOF) {
		return [32]byte{}, fmt.Errorf("checksum read is incomplete: %w", errors.Join(err, extraErr, io.ErrUnexpectedEOF))
	}
	return [32]byte(hash.Sum(nil)), nil
}

// OCI HEAD errors have no service code, so a 404 cannot distinguish an absent
// object from refused access. GET supplies ObjectNotFound; close immediately
// after receiving metadata rather than downloading the body.
func (c *copier) metadata(ctx context.Context, bucket, name string) (objectstorage.GetObjectResponse, error) {
	response, err := c.target.GetObject(ctx, objectstorage.GetObjectRequest{NamespaceName: &c.namespace, BucketName: &bucket, ObjectName: &name})
	if err != nil {
		return response, err
	}
	if response.Content == nil {
		return response, errors.New("backfill metadata read returned no body")
	}
	return response, response.Content.Close()
}

func (c *copier) waitCopy(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	for {
		r, err := c.source.GetWorkRequest(ctx, objectstorage.GetWorkRequestRequest{WorkRequestId: &id})
		if err != nil {
			return err
		}
		switch r.Status {
		case objectstorage.WorkRequestStatusCompleted:
			return nil
		case objectstorage.WorkRequestStatusFailed, objectstorage.WorkRequestStatusCanceled:
			return fmt.Errorf("Object Storage copy %s ended in %s", id, r.Status)
		case objectstorage.WorkRequestStatusAccepted, objectstorage.WorkRequestStatusInProgress, objectstorage.WorkRequestStatusCanceling:
		default:
			return fmt.Errorf("Object Storage copy %s has unknown status %s", id, r.Status)
		}
		if err := c.Pause(ctx, 2*time.Second); err != nil {
			return err
		}
	}
}

func same(value *string, want string) bool { return value != nil && *value == want }
func ociError(err error, status int, code string) bool {
	service, ok := errors.AsType[serviceError](err)
	return ok && service.GetHTTPStatusCode() == status && service.GetCode() == code
}
