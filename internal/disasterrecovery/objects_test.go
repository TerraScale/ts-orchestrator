package disasterrecovery

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

type fakeObjects struct {
	objectClient
	buckets      map[string]objectstorage.Bucket
	policy       *objectstorage.ReplicationPolicySummary
	pages        [][]objectstorage.ObjectSummary
	heads        map[string]objectstorage.HeadObjectResponse
	mirror       map[string]objectstorage.HeadObjectResponse
	mu           *sync.Mutex // Shared by both regions; backfill workers call them concurrently.
	copies       []objectstorage.CopyObjectRequest
	creates      int
	list         int
	retention    bool
	copyErr      error
	copyErrs     map[string]error // By source object name.
	beforeCopy   func(objectstorage.CopyObjectRequest)
	status       objectstorage.WorkRequestStatusEnum
	remote       *fakeObjects
	createErr    error
	omitCreateID bool
	afterCreate  func()
	afterList    func()
	afterCopy    func()
}

func (f *fakeObjects) GetBucket(_ context.Context, r objectstorage.GetBucketRequest) (objectstorage.GetBucketResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if b, ok := f.buckets[*r.BucketName]; ok {
		return objectstorage.GetBucketResponse{Bucket: b}, nil
	}
	return objectstorage.GetBucketResponse{}, newServiceFailure(http.StatusNotFound, "BucketNotFound", "missing", "request")
}
func (f *fakeObjects) CreateBucket(_ context.Context, r objectstorage.CreateBucketRequest) (objectstorage.CreateBucketResponse, error) {
	f.creates++
	b := objectstorage.Bucket{Id: new(fmt.Sprintf("ocid1.bucket.oc1.us-sanjose-1.bucket%d", f.creates)), Name: r.Name, Namespace: r.NamespaceName, CompartmentId: r.CompartmentId, KmsKeyId: r.KmsKeyId,
		PublicAccessType: objectstorage.BucketPublicAccessTypeEnum(r.PublicAccessType), StorageTier: objectstorage.BucketStorageTierEnum(r.StorageTier),
		Versioning: objectstorage.BucketVersioningEnum(r.Versioning), IsReadOnly: new(false), ReplicationEnabled: new(false), FreeformTags: r.FreeformTags}
	f.buckets[*r.Name] = b
	if f.afterCreate != nil {
		f.afterCreate()
	}
	if f.createErr != nil {
		return objectstorage.CreateBucketResponse{}, f.createErr
	}
	if f.omitCreateID {
		b.Id = nil
	}
	return objectstorage.CreateBucketResponse{Bucket: b}, nil
}
func (f *fakeObjects) ListRetentionRules(context.Context, objectstorage.ListRetentionRulesRequest) (objectstorage.ListRetentionRulesResponse, error) {
	r := objectstorage.ListRetentionRulesResponse{}
	if f.retention {
		r.Items = []objectstorage.RetentionRuleSummary{{}}
	}
	return r, nil
}
func (f *fakeObjects) ListReplicationPolicies(context.Context, objectstorage.ListReplicationPoliciesRequest) (objectstorage.ListReplicationPoliciesResponse, error) {
	r := objectstorage.ListReplicationPoliciesResponse{}
	if f.policy != nil {
		r.Items = []objectstorage.ReplicationPolicySummary{*f.policy}
	}
	return r, nil
}
func (f *fakeObjects) CreateReplicationPolicy(_ context.Context, r objectstorage.CreateReplicationPolicyRequest) (objectstorage.CreateReplicationPolicyResponse, error) {
	f.creates++
	f.policy = &objectstorage.ReplicationPolicySummary{Id: new("policy-1"), Name: r.Name, DestinationBucketName: r.DestinationBucketName,
		DestinationRegionName: r.DestinationRegionName, Status: objectstorage.ReplicationPolicySummaryStatusActive}
	if f.remote != nil {
		b := f.remote.buckets[*r.DestinationBucketName]
		b.IsReadOnly = new(true)
		f.remote.buckets[*r.DestinationBucketName] = b
	}
	response := objectstorage.CreateReplicationPolicyResponse{ReplicationPolicy: objectstorage.ReplicationPolicy{
		Id: f.policy.Id, Name: f.policy.Name, DestinationRegionName: f.policy.DestinationRegionName,
		DestinationBucketName: f.policy.DestinationBucketName, Status: objectstorage.ReplicationPolicyStatusEnum(f.policy.Status)}}
	if f.afterCreate != nil {
		f.afterCreate()
	}
	if f.createErr != nil {
		return objectstorage.CreateReplicationPolicyResponse{}, f.createErr
	}
	if f.omitCreateID {
		response.Id = nil
	}
	return response, nil
}
func (f *fakeObjects) ListObjects(_ context.Context, r objectstorage.ListObjectsRequest) (objectstorage.ListObjectsResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.list
	f.list++
	if f.afterList != nil {
		f.afterList()
	}
	response := objectstorage.ListObjectsResponse{}
	if i < len(f.pages) {
		response.Objects = f.pages[i]
	}
	if i+1 < len(f.pages) {
		response.NextStartWith = new("next")
	}
	return response, nil
}
func (f *fakeObjects) GetObject(_ context.Context, r objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if *r.BucketName == "gru-1-backup" {
		for _, page := range f.pages {
			for _, object := range page {
				if *object.Name == *r.ObjectName {
					return objectstorage.GetObjectResponse{ContentLength: object.Size, ContentMd5: object.Md5, ETag: object.Etag, Content: io.NopCloser(strings.NewReader("contents"))}, nil
				}
			}
		}
	}
	heads := f.heads
	if *r.BucketName == "sfo-1-dr-gru-1-backup" {
		heads = f.mirror
	}
	if h, ok := heads[*r.ObjectName]; ok {
		return objectstorage.GetObjectResponse{ContentLength: h.ContentLength, ContentMd5: h.ContentMd5, ETag: h.ETag,
			Content: io.NopCloser(strings.NewReader("contents"))}, nil
	}
	return objectstorage.GetObjectResponse{}, newServiceFailure(http.StatusNotFound, "ObjectNotFound", "missing", "request")
}
func (f *fakeObjects) CopyObject(_ context.Context, r objectstorage.CopyObjectRequest) (objectstorage.CopyObjectResponse, error) {
	if f.beforeCopy != nil {
		f.beforeCopy(r)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.copies = append(f.copies, r)
	if f.copyErr != nil {
		return objectstorage.CopyObjectResponse{}, f.copyErr
	}
	if err := f.copyErrs[*r.SourceObjectName]; err != nil {
		return objectstorage.CopyObjectResponse{}, err
	}
	f.heads[*r.SourceObjectName] = objectstorage.HeadObjectResponse{ContentLength: new(int64(8)), ContentMd5: new("checksum"), ETag: new("copy-etag")}
	if f.afterCopy != nil {
		f.afterCopy()
	}
	return objectstorage.CopyObjectResponse{OpcWorkRequestId: new("copy-1")}, nil
}
func (f *fakeObjects) GetWorkRequest(context.Context, objectstorage.GetWorkRequestRequest) (objectstorage.GetWorkRequestResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return objectstorage.GetWorkRequestResponse{WorkRequest: objectstorage.WorkRequest{Status: f.status}}, nil
}

func objectFixture() (*copier, *fakeObjects, *fakeObjects) {
	mu := &sync.Mutex{}
	s := &fakeObjects{buckets: map[string]objectstorage.Bucket{}, heads: map[string]objectstorage.HeadObjectResponse{}, status: objectstorage.WorkRequestStatusCompleted, mu: mu}
	t := &fakeObjects{buckets: map[string]objectstorage.Bucket{}, heads: s.heads, mu: mu}
	s.remote = t
	c := &copier{source: s, target: t, namespace: "namespace", sourceRegion: "sa-saopaulo-1", targetRegion: "us-sanjose-1",
		sourceCell: "gru", targetCell: "sfo", sourceConfig: Region{CompartmentID: "gru-control", KeyID: "gru-key"},
		targetConfig: Region{CompartmentID: "sfo-control", KeyID: "sfo-key"}, Pause: func(context.Context, time.Duration) error { return nil }}
	s.buckets["gru-1-backup"] = objectstorage.Bucket{Name: new("gru-1-backup"), Namespace: &c.namespace, CompartmentId: &c.sourceConfig.CompartmentID,
		KmsKeyId: &c.sourceConfig.KeyID, PublicAccessType: objectstorage.BucketPublicAccessTypeNopublicaccess,
		StorageTier: objectstorage.BucketStorageTierStandard, IsReadOnly: new(false)}
	return c, s, t
}

func TestCopyPlansWithoutWrites(t *testing.T) {
	c, s, d := objectFixture()
	r, err := c.copy(t.Context(), "backup")
	if err != nil || !r.Planned || r.MirrorBucket == r.SourceBucket || r.SeedBucket == r.MirrorBucket || s.creates+d.creates != 0 || s.list != 0 {
		t.Fatalf("plan = %+v, %v, writes=%d", r, err, s.creates+d.creates)
	}
}

func TestCopyActivatesMirrorBeforeBackfillAndVerifiesAllPages(t *testing.T) {
	c, s, d := objectFixture()
	c.apply = true
	s.pages = [][]objectstorage.ObjectSummary{{{Name: new("v1/keys/project/key"), Size: new(int64(8)), Md5: new("checksum"), Etag: new("source-key")}},
		{{Name: new("v1/db/snapshot"), Size: new(int64(8)), Md5: new("checksum"), Etag: new("source-snapshot")}}}
	r, err := c.copy(t.Context(), "backup")
	if err != nil || r.Seeded != 2 || r.PolicyID != "policy-1" || len(s.copies) != 2 || d.creates != 2 || s.list != 2 {
		t.Fatalf("copy = %+v, %v, requests=%+v", r, err, s.copies)
	}
	if !same(d.buckets[r.MirrorBucket].Id, r.MirrorBucketID) || !same(d.buckets[r.SeedBucket].Id, r.SeedBucketID) {
		t.Fatalf("created bucket IDs missing from report: %+v", r)
	}
	if !same(d.buckets[r.MirrorBucket].KmsKeyId, "sfo-key") || !same(d.buckets[r.SeedBucket].KmsKeyId, "sfo-key") {
		t.Fatal("destination buckets must pin the target region's encryption key")
	}
	for _, copy := range s.copies {
		if *copy.BucketName != "gru-1-backup" || *copy.DestinationBucket != r.SeedBucket || copy.SourceObjectIfMatchETag == nil ||
			!same(copy.DestinationObjectIfNoneMatchETag, "*") || copy.OpcSseKmsKeyId != nil ||
			*copy.SourceObjectName != *copy.DestinationObjectName {
			t.Fatalf("copy is not pinned to source version and regional seed: %+v", copy)
		}
	}
	// The operator reviews the report IDs and pins them before resuming.
	pinCopyReport(c, r)
	s.list = 0
	_, err = c.copy(t.Context(), "backup")
	if err != nil || s.creates != 1 || d.creates != 2 || len(s.copies) != 2 {
		t.Fatalf("resume: %v, %+v", err, s.copies)
	}
}

func TestBackfillSkipsIdenticalMirrorCopiesAndCopiesConcurrently(t *testing.T) {
	c, s, d := objectFixture()
	c.apply = true
	c.workers = 4
	d.mirror = map[string]objectstorage.HeadObjectResponse{}
	var pages [][]objectstorage.ObjectSummary
	for page := range 2 {
		var objects []objectstorage.ObjectSummary
		for i := range 5 {
			name := fmt.Sprintf("v1/db/wal/%d-%d", page, i)
			objects = append(objects, objectstorage.ObjectSummary{Name: new(name), Size: new(int64(8)), Md5: new("checksum"), Etag: new(name)})
			md5 := "checksum"
			if i == 4 {
				md5 = "older version"
			}
			if i >= 2 {
				d.mirror[name] = objectstorage.HeadObjectResponse{ContentLength: new(int64(8)), ContentMd5: new(md5), ETag: new("mirror")}
			}
		}
		pages = append(pages, objects)
	}
	s.pages = pages
	r, err := c.copy(t.Context(), "backup")
	if err != nil || r.Seeded != 6 || r.Mirrored != 4 || len(s.copies) != 6 {
		t.Fatalf("copy = %+v, %v, copies=%d", r, err, len(s.copies))
	}
	for _, copy := range s.copies {
		if name := *copy.SourceObjectName; strings.HasSuffix(name, "-2") || strings.HasSuffix(name, "-3") {
			t.Fatalf("identical mirror object %s was seeded again", name)
		}
	}
}

func TestBackfillDrainsSubmittedCopiesAfterASiblingFails(t *testing.T) {
	c, s, _ := objectFixture()
	c.apply = true
	c.workers = 2
	s.pages = [][]objectstorage.ObjectSummary{{{Name: new("v1/a"), Size: new(int64(8)), Md5: new("checksum"), Etag: new("a")},
		{Name: new("v1/b"), Size: new(int64(8)), Md5: new("checksum"), Etag: new("b")}}}
	s.copyErrs = map[string]error{"v1/a": newServiceFailure(http.StatusPreconditionFailed, "PreconditionFailed", "moved", "request")}
	// v1/a fails only after v1/b's server-side copy is running.
	submitted := make(chan struct{})
	s.beforeCopy = func(r objectstorage.CopyObjectRequest) {
		if *r.SourceObjectName == "v1/a" {
			<-submitted
		}
	}
	s.afterCopy = func() { close(submitted) }
	s.status = objectstorage.WorkRequestStatusInProgress
	c.Pause = func(ctx context.Context, _ time.Duration) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
		s.mu.Lock()
		s.status = objectstorage.WorkRequestStatusCompleted
		s.mu.Unlock()
		return nil
	}
	r, err := c.copy(t.Context(), "backup")
	if err == nil || r.Seeded != 1 {
		t.Fatalf("submitted copy abandoned after a sibling failed: %+v, %v", r, err)
	}
}

func TestBackfillRechecksTheMirrorBeforeSuccess(t *testing.T) {
	c, s, d := objectFixture()
	c.apply = true
	s.pages = [][]objectstorage.ObjectSummary{{{Name: new("v1/db/wal/0"), Size: new(int64(8)), Md5: new("checksum"), Etag: new("source")}}}
	d.mirror = map[string]objectstorage.HeadObjectResponse{"v1/db/wal/0": {ContentLength: new(int64(8)), ContentMd5: new("checksum"), ETag: new("mirror")}}
	s.afterList = func() {
		mirror := d.buckets["sfo-1-dr-gru-1-backup"]
		mirror.Id = new("ocid1.bucket.oc1.us-sanjose-1.replacement")
		d.buckets[*mirror.Name] = mirror
	}
	if r, err := c.copy(t.Context(), "backup"); err == nil || r.Mirrored != 1 || len(s.copies) != 0 {
		t.Fatalf("replaced mirror accepted: %+v, %v", r, err)
	}
}

func TestCopyRefusesConflictingResourcesBeforeMutation(t *testing.T) {
	for _, reason := range []string{"source compartment", "source key", "existing policy", "destination ownership", "retention"} {
		t.Run(reason, func(t *testing.T) {
			c, s, d := objectFixture()
			c.apply = true
			b := s.buckets["gru-1-backup"]
			switch reason {
			case "source compartment":
				b.CompartmentId = new("unrelated")
			case "source key":
				b.KmsKeyId = new("unrelated")
			case "existing policy":
				s.policy = &objectstorage.ReplicationPolicySummary{Id: new("0000000000V4MRM46HP1SNGDYW"), Name: new("0000000000V4MRM46HP1SNGDYW")}
			case "destination ownership":
				d.buckets["sfo-1-dr-gru-1-backup"] = objectstorage.Bucket{Name: new("sfo-1-dr-gru-1-backup")}
			case "retention":
				id, err := c.bucket(t.Context(), "sfo-1-dr-gru-1-backup", "", false, true)
				if err != nil {
					t.Fatal(err)
				}
				c.targetConfig.BucketIDs = map[string]string{"sfo-1-dr-gru-1-backup": id}
				d.creates = 0
				d.retention = true
			}
			s.buckets["gru-1-backup"] = b
			if _, err := c.copy(t.Context(), "backup"); err == nil || s.creates+d.creates != 0 {
				t.Fatalf("unsafe admission: %v, writes=%d", err, s.creates+d.creates)
			}
		})
	}
}

func TestBackfillFailsClosedWhenSourceMovesOrCopyNeverCompletes(t *testing.T) {
	for _, reason := range []string{"source moves", "cancel", "unknown state", "no size"} {
		t.Run(reason, func(t *testing.T) {
			c, s, _ := objectFixture()
			c.apply = true
			s.pages = [][]objectstorage.ObjectSummary{{{Name: new("v1/snapshot"), Size: new(int64(8)), Md5: new("checksum"), Etag: new("source")}}}
			switch reason {
			case "source moves":
				s.copyErr = newServiceFailure(http.StatusPreconditionFailed, "PreconditionFailed", "moved", "request")
			case "cancel":
				s.status = objectstorage.WorkRequestStatusInProgress
				c.Pause = func(context.Context, time.Duration) error { return context.Canceled }
			case "unknown state":
				s.status = "UNRECOGNIZED"
			case "no size":
				s.pages[0][0].Size = nil
			}
			if _, err := c.copy(t.Context(), "backup"); err == nil {
				t.Fatal("incomplete backfill accepted")
			}
		})
	}
}

func TestBackfillHashesMultipartAndMissingChecksums(t *testing.T) {
	for _, checksum := range []*string{nil, new("multipart-2")} {
		c, s, _ := objectFixture()
		c.apply = true
		s.pages = [][]objectstorage.ObjectSummary{{{Name: new("v1/large-snapshot"), Size: new(int64(8)), Md5: checksum, Etag: new("source")}}}
		r, err := c.copy(t.Context(), "backup")
		if err != nil || r.Seeded != 1 {
			t.Fatalf("multipart/missing checksum: %+v,%v", r, err)
		}
	}
}

func pinCopyReport(c *copier, r CopyReport) {
	c.targetConfig.BucketIDs = map[string]string{r.MirrorBucket: r.MirrorBucketID, r.SeedBucket: r.SeedBucketID}
	c.sourceConfig.PolicyIDs = map[string]string{"TS-641-" + r.SourceBucket: r.PolicyID}
}

func TestCopyRefusesUnpinnedAndReplacedResources(t *testing.T) {
	for _, resource := range []string{"mirror", "seed", "policy"} {
		for _, unpinned := range []bool{true, false} {
			for _, apply := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/unpinned=%t/apply=%t", resource, unpinned, apply), func(t *testing.T) {
					c, s, d := objectFixture()
					c.apply = true
					r, err := c.copy(t.Context(), "backup")
					if err != nil {
						t.Fatal(err)
					}
					pinCopyReport(c, r)
					if resource == "policy" {
						if unpinned {
							c.sourceConfig.PolicyIDs = nil
						} else {
							s.policy.Id = new("same-name-replacement")
						}
					} else {
						name := r.MirrorBucket
						if resource == "seed" {
							name = r.SeedBucket
						}
						if unpinned {
							delete(c.targetConfig.BucketIDs, name)
						} else {
							b := d.buckets[name]
							// Keep identical names, settings and TS-641 tags.
							b.Id = new("ocid1.bucket.oc1.us-sanjose-1.replacement")
							d.buckets[name] = b
						}
					}
					c.apply = apply
					s.creates, d.creates, s.list = 0, 0, 0
					if _, err := c.copy(t.Context(), "backup"); err == nil || s.creates+d.creates != 0 || s.list != 0 {
						t.Fatalf("unowned resource admitted: %v, writes=%d, inventories=%d", err, s.creates+d.creates, s.list)
					}
				})
			}
		}
	}
}

func TestCopyDoesNotRecreateMissingPinnedResources(t *testing.T) {
	for _, resource := range []string{"mirror", "seed", "policy"} {
		t.Run(resource, func(t *testing.T) {
			c, s, d := objectFixture()
			c.apply = true
			r, err := c.copy(t.Context(), "backup")
			if err != nil {
				t.Fatal(err)
			}
			pinCopyReport(c, r)
			switch resource {
			case "mirror":
				delete(d.buckets, r.MirrorBucket)
			case "seed":
				delete(d.buckets, r.SeedBucket)
			case "policy":
				s.policy = nil
			}
			s.creates, d.creates = 0, 0
			if _, err := c.copy(t.Context(), "backup"); err == nil || s.creates+d.creates != 0 {
				t.Fatalf("missing pinned resource recreated: %v, writes=%d", err, s.creates+d.creates)
			}
		})
	}
}

func TestCopyRechecksPinnedPolicyBeforeBackfill(t *testing.T) {
	c, s, d := objectFixture()
	c.apply = true
	r, err := c.copy(t.Context(), "backup")
	if err != nil {
		t.Fatal(err)
	}
	pinCopyReport(c, r)
	// An unpinned, absent seed may be created, but that cannot admit a
	// same-name policy replacement appearing after the initial inspection.
	delete(d.buckets, r.SeedBucket)
	delete(c.targetConfig.BucketIDs, r.SeedBucket)
	d.afterCreate = func() { s.policy.Id = new("same-name-replacement") }
	s.list = 0
	if _, err := c.copy(t.Context(), "backup"); err == nil || s.list != 0 {
		t.Fatalf("policy replacement admitted before backfill: %v, inventories=%d", err, s.list)
	}
}

func TestCopyRechecksDestinationIDsAcrossProvisioningSteps(t *testing.T) {
	for _, resource := range []string{"mirror", "0000000000SF1REEJJX6TC691V"} {
		t.Run(resource, func(t *testing.T) {
			c, s, d := objectFixture()
			c.apply = true
			s.pages = [][]objectstorage.ObjectSummary{{{Name: new("v1/snapshot"), Size: new(int64(8)), Md5: new("checksum"), Etag: new("source")}}}
			replace := func(name string) {
				bucket := d.buckets[name]
				bucket.Id = new("ocid1.bucket.oc1.us-sanjose-1.replacement")
				d.buckets[name] = bucket
			}
			if resource == "mirror" {
				d.afterCreate = func() {
					if d.creates == 2 {
						replace("sfo-1-dr-gru-1-backup")
					}
				}
			} else {
				s.afterCreate = func() { replace("sfo-1-dr-gru-1-backup-seed") }
			}
			r, err := c.copy(t.Context(), "backup")
			if err == nil || len(s.copies) != 0 || s.list != 0 {
				t.Fatalf("replacement received copies: report=%+v err=%v copies=%d inventories=%d", r, err, len(s.copies), s.list)
			}
			if resource == "mirror" && s.creates != 0 {
				t.Fatal("replacement mirror received a replication policy")
			}
		})
	}
}

func TestCopyRechecksSeedIDDuringInventoryAndBetweenCopies(t *testing.T) {
	for _, boundary := range []string{"inventory", "between copies", "completion"} {
		t.Run(boundary, func(t *testing.T) {
			c, s, d := objectFixture()
			c.apply = true
			objects := []objectstorage.ObjectSummary{{Name: new("v1/first"), Size: new(int64(8)), Md5: new("checksum"), Etag: new("first")}}
			if boundary != "completion" {
				objects = append(objects, objectstorage.ObjectSummary{Name: new("v1/second"), Size: new(int64(8)), Md5: new("checksum"), Etag: new("second")})
			}
			s.pages = [][]objectstorage.ObjectSummary{objects}
			replace := func() {
				bucket := d.buckets["sfo-1-dr-gru-1-backup-seed"]
				bucket.Id = new("ocid1.bucket.oc1.us-sanjose-1.replacement")
				d.buckets[*bucket.Name] = bucket
			}
			wantCopies := 1
			if boundary == "inventory" {
				s.afterList = replace
				wantCopies = 0
			} else {
				s.afterCopy = replace
			}
			r, err := c.copy(t.Context(), "backup")
			if err == nil || len(s.copies) != wantCopies || r.Seeded != wantCopies {
				t.Fatalf("replacement admitted at %s: report=%+v err=%v copies=%d", boundary, r, err, len(s.copies))
			}
		})
	}
}

func TestCopyCannotAdoptLostOrUnknownCreateResponsesOnResume(t *testing.T) {
	for _, policy := range []bool{false, true} {
		for _, lost := range []bool{false, true} {
			t.Run(fmt.Sprintf("policy=%t/lost=%t", policy, lost), func(t *testing.T) {
				c, s, d := objectFixture()
				c.apply = true
				f := d
				if policy {
					f = s
				}
				if lost {
					f.createErr = errors.New("create accepted but response lost")
				} else {
					f.omitCreateID = true
				}
				r, err := c.copy(t.Context(), "backup")
				if err == nil || s.list != 0 || (policy && r.PolicyID != "") || (!policy && r.MirrorBucketID != "") {
					t.Fatalf("unknown create admitted: %+v, %v", r, err)
				}
				if policy {
					// Only successful bucket responses can be reviewed and pinned.
					c.targetConfig.BucketIDs = map[string]string{r.MirrorBucket: r.MirrorBucketID, r.SeedBucket: r.SeedBucketID}
				}
				f.createErr, f.omitCreateID = nil, false
				before := s.creates + d.creates
				resumed := *c
				if _, err := resumed.copy(t.Context(), "backup"); err == nil || s.creates+d.creates != before || s.list != 0 {
					t.Fatalf("lost create adopted on resume: %v, writes=%d", err, s.creates+d.creates-before)
				}
			})
		}
	}
}

func TestCopyReportsSuccessfulCreateIDsAfterLaterFailure(t *testing.T) {
	for _, failure := range []string{"mirror readback", "mirror replacement", "seed response lost", "policy replacement", "policy not visible", "backfill"} {
		t.Run(failure, func(t *testing.T) {
			c, s, d := objectFixture()
			c.apply = true
			switch failure {
			case "mirror readback":
				d.afterCreate = func() { d.retention = true }
			case "mirror replacement":
				d.afterCreate = func() {
					b := d.buckets["sfo-1-dr-gru-1-backup"]
					b.Id = new("ocid1.bucket.oc1.us-sanjose-1.replacement")
					d.buckets[*b.Name] = b
				}
			case "seed response lost":
				d.afterCreate = func() {
					if d.creates == 2 {
						d.createErr = errors.New("seed created but response lost")
					}
				}
			case "policy replacement":
				s.afterCreate = func() { s.policy.Id = new("same-name-replacement") }
			case "policy not visible":
				s.afterCreate = func() { s.policy = nil }
			case "backfill":
				s.pages = [][]objectstorage.ObjectSummary{{{Name: new("snapshot"), Size: new(int64(8)), Md5: new("checksum"), Etag: new("source")}}}
				s.copyErr = errors.New("copy failed")
			}
			r, err := c.copy(t.Context(), "backup")
			if err == nil {
				t.Fatal("failure accepted")
			}
			want := map[string]string{"mirror_bucket_id": "ocid1.bucket.oc1.us-sanjose-1.bucket1"}
			if strings.HasPrefix(failure, "policy") || failure == "backfill" {
				want["seed_bucket_id"] = "ocid1.bucket.oc1.us-sanjose-1.bucket2"
				want["policy_id"] = "policy-1"
			} else if r.SeedBucketID != "" || r.PolicyID != "" {
				t.Fatalf("untrusted IDs reported: %+v", r)
			}
			data, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			var report map[string]any
			if err := json.Unmarshal(data, &report); err != nil {
				t.Fatal(err)
			}
			for field, id := range want {
				if report[field] != id {
					t.Fatalf("report lost successful %s after %s: %s", field, failure, data)
				}
			}
		})
	}
}

func TestConfigRejectsCrossedRegionsAndSharedCompartments(t *testing.T) {
	valid := configFixture()
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.SFO.KeyID = c.GRU.KeyID }, func(c *Config) { c.SFO.CompartmentID = c.GRU.CompartmentID }, func(c *Config) { c.Version = 2 }} {
		c := valid
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Fatalf("invalid config accepted: %+v", c)
		}
	}
	if !ociError(newServiceFailure(404, "ObjectNotFound", "missing", "r"), 404, "ObjectNotFound") || ociError(errors.New("404"), 404, "ObjectNotFound") {
		t.Fatal("missing object classification")
	}
}

func configFixture() Config {
	return Config{Version: 1, Namespace: "namespace", GRU: Region{CompartmentID: "ocid1.compartment.oc1..gru", VaultID: "ocid1.vault.oc1.sa-saopaulo-1.gru", KeyID: "ocid1.key.oc1.sa-saopaulo-1.gru"},
		SFO: Region{CompartmentID: "ocid1.compartment.oc1..sfo", VaultID: "ocid1.vault.oc1.us-sanjose-1.sfo", KeyID: "ocid1.key.oc1.us-sanjose-1.sfo"}}
}

func TestConfigValidatesReviewedResourceNamesAndIDs(t *testing.T) {
	valid := func() Config {
		c := configFixture()
		c.GRU.BucketIDs = map[string]string{"gru-1-dr-sfo-1-backup": "ocid1.bucket.oc1.sa-saopaulo-1.mirror", "gru-1-dr-sfo-1-backup-seed": "ocid1.bucket.oc1.sa-saopaulo-1.seed"}
		c.SFO.BucketIDs = map[string]string{"sfo-1-dr-gru-1-head": "ocid1.bucket.oc1.us-sanjose-1.mirror", "sfo-1-dr-gru-1-head-seed": "ocid1.bucket.oc1.us-sanjose-1.seed"}
		c.GRU.PolicyIDs = map[string]string{"TS-641-gru-1-backup": "0J6HB7G4HM28T14D0J6HB7H6NW"}
		c.SFO.PolicyIDs = map[string]string{"TS-641-sfo-1-head": "47CN1J24HM28T14D0J6HB7H6NW"}
		return c
	}
	if err := valid().Validate(); err != nil {
		t.Fatalf("reviewed regional OCIDs and opaque policy UUIDs rejected: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"serving bucket":           func(c *Config) { c.GRU.BucketIDs["gru-1-backup"] = "ocid1.bucket.oc1.sa-saopaulo-1.other" },
		"crossed destination name": func(c *Config) { c.GRU.BucketIDs["sfo-1-dr-gru-1-backup"] = "ocid1.bucket.oc1.sa-saopaulo-1.other" },
		"wrong bucket region":      func(c *Config) { c.GRU.BucketIDs["gru-1-dr-sfo-1-backup"] = "ocid1.bucket.oc1.us-sanjose-1.other" },
		"wrong bucket type":        func(c *Config) { c.GRU.BucketIDs["gru-1-dr-sfo-1-backup"] = c.GRU.KeyID },
		"empty bucket ID":          func(c *Config) { c.GRU.BucketIDs["gru-1-dr-sfo-1-backup"] = "" },
		"duplicate bucket ID": func(c *Config) {
			c.GRU.BucketIDs["gru-1-dr-sfo-1-backup-seed"] = c.GRU.BucketIDs["gru-1-dr-sfo-1-backup"]
		},
		"unexpected policy name": func(c *Config) { c.GRU.PolicyIDs["0000000000V4MRM46HP1SNGDYW"] = "policy-2" },
		"crossed policy name":    func(c *Config) { c.GRU.PolicyIDs["TS-641-sfo-1-head"] = "policy-2" },
		"empty policy ID":        func(c *Config) { c.GRU.PolicyIDs["TS-641-gru-1-backup"] = "" },
		"malformed policy ID":    func(c *Config) { c.GRU.PolicyIDs["TS-641-gru-1-backup"] = "policy\nreplacement" },
		"duplicate policy ID":    func(c *Config) { c.GRU.PolicyIDs["TS-641-gru-1-head"] = c.GRU.PolicyIDs["TS-641-gru-1-backup"] },
	} {
		t.Run(name, func(t *testing.T) {
			c := valid()
			mutate(&c)
			if err := c.Validate(); err == nil {
				t.Fatal("unexpected resource name or ID accepted")
			}
		})
	}
}

type fakeServiceFailure struct {
	status int
	code   string
}

func (e fakeServiceFailure) Error() string           { return e.code }
func (e fakeServiceFailure) GetHTTPStatusCode() int  { return e.status }
func (e fakeServiceFailure) GetCode() string         { return e.code }
func (e fakeServiceFailure) GetMessage() string      { return e.code }
func (e fakeServiceFailure) GetOpcRequestID() string { return "request" }
func newServiceFailure(status int, code, message, request string) error {
	return fakeServiceFailure{status, code}
}
