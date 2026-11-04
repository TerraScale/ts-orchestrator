package disasterrecovery

import (
	"context"
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
	if *r.BucketName == "sjc-1-dr-gru-1-backup" {
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
		sourceCell: "gru", targetCell: "sjc", sourceConfig: Region{CompartmentID: "gru-control", KeyID: "gru-key"},
		targetConfig: Region{CompartmentID: "sjc-control", KeyID: "sjc-key"}, Pause: func(context.Context, time.Duration) error { return nil }}
	s.buckets["gru-1-backup"] = objectstorage.Bucket{Name: new("gru-1-backup"), Namespace: &c.namespace, CompartmentId: &c.sourceConfig.CompartmentID,
		KmsKeyId: &c.sourceConfig.KeyID, PublicAccessType: objectstorage.BucketPublicAccessTypeNopublicaccess,
		StorageTier: objectstorage.BucketStorageTierStandard, IsReadOnly: new(false)}
	return c, s, t
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
	if !same(d.buckets[r.MirrorBucket].KmsKeyId, "sjc-key") || !same(d.buckets[r.SeedBucket].KmsKeyId, "sjc-key") {
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

func TestBackfillRechecksTheMirrorBeforeSuccess(t *testing.T) {
	c, s, d := objectFixture()
	c.apply = true
	s.pages = [][]objectstorage.ObjectSummary{{{Name: new("v1/db/wal/0"), Size: new(int64(8)), Md5: new("checksum"), Etag: new("source")}}}
	d.mirror = map[string]objectstorage.HeadObjectResponse{"v1/db/wal/0": {ContentLength: new(int64(8)), ContentMd5: new("checksum"), ETag: new("mirror")}}
	s.afterList = func() {
		mirror := d.buckets["sjc-1-dr-gru-1-backup"]
		mirror.Id = new("ocid1.bucket.oc1.us-sanjose-1.replacement")
		d.buckets[*mirror.Name] = mirror
	}
	if r, err := c.copy(t.Context(), "backup"); err == nil || r.Mirrored != 1 || len(s.copies) != 0 {
		t.Fatalf("replaced mirror accepted: %+v, %v", r, err)
	}
}

func pinCopyReport(c *copier, r CopyReport) {
	c.targetConfig.BucketIDs = map[string]string{r.MirrorBucket: r.MirrorBucketID, r.SeedBucket: r.SeedBucketID}
	c.sourceConfig.PolicyIDs = map[string]string{"TS-641-" + r.SourceBucket: r.PolicyID}
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
