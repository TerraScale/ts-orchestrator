package cli

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// membershipBucket serves one cell's head-bucket status reads; failure fails
// the object read the way an OCI error would.
type membershipBucket struct {
	objects map[string][]byte
	failure error
}

func (bucket *membershipBucket) GetObject(_ context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	if bucket.failure != nil {
		return objectstorage.GetObjectResponse{}, bucket.failure
	}
	data, ok := bucket.objects[*request.ObjectName]
	if !ok {
		return objectstorage.GetObjectResponse{}, httpError(404)
	}
	return objectstorage.GetObjectResponse{Content: io.NopCloser(bytes.NewReader(data)), ETag: new("etag")}, nil
}

func (bucket *membershipBucket) PutObject(context.Context, objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error) {
	return objectstorage.PutObjectResponse{}, errors.New("read-only membership bucket")
}

func membershipStatus(cell string, updated time.Time) []byte {
	status := releasechannel.Status{Schema: releasechannel.StatusSchema, Cell: cell, Environment: "production",
		Architectures: []string{"amd64"}, UpdatedAt: updated}
	wire, err := json.Marshal(status)
	if err != nil {
		panic(err)
	}
	return wire
}

func membershipFixture(now time.Time) map[string]*membershipBucket {
	buckets := map[string]*membershipBucket{}
	for _, cell := range []string{"GRU", "SJC", "FRA"} {
		buckets[cell] = &membershipBucket{objects: map[string][]byte{
			releasechannel.StatusObject: membershipStatus(cell, now),
		}}
	}
	return buckets
}

func membershipOpen(buckets map[string]*membershipBucket) func(context.Context, string) (releasechannel.Location, error) {
	return func(_ context.Context, cell string) (releasechannel.Location, error) {
		bucket, ok := buckets[cell]
		if !ok {
			return releasechannel.Location{}, errors.New("no such cell")
		}
		return releasechannel.Location{Client: bucket, Namespace: "ns", Bucket: strings.ToLower(cell) + "-head"}, nil
	}
}

// TestServingCellsDiscovery serves every founded cell's status from its own
// head bucket and reads the fleet through the same bucket interface the
// release channel uses; a cell whose status object is authoritatively absent
// is not serving, while any failed or stale probe fails the whole discovery
// instead of silently narrowing the fleet.
func TestServingCellsDiscovery(t *testing.T) {
	now := time.Now().UTC()
	buckets := membershipFixture(now)
	open := membershipOpen(buckets)

	cells, err := servingCells(t.Context(), open, now)
	if err != nil {
		t.Fatalf("servingCells: %v", err)
	}
	if !strings.EqualFold(strings.Join(cells, ","), "GRU,SJC,FRA") {
		t.Fatalf("servingCells = %q, want GRU,SJC,FRA", cells)
	}

	delete(buckets["FRA"].objects, releasechannel.StatusObject)
	cells, err = servingCells(t.Context(), open, now)
	if err != nil {
		t.Fatalf("servingCells without FRA's status: %v", err)
	}
	if !strings.EqualFold(strings.Join(cells, ","), "GRU,SJC") || slices.Contains(cells, "FRA") {
		t.Fatalf("servingCells = %q, want GRU,SJC without FRA", cells)
	}

	buckets["SJC"].failure = httpError(401)
	if _, err = servingCells(t.Context(), open, now); err == nil || !strings.Contains(err.Error(), "SJC") || !strings.Contains(err.Error(), "401") {
		t.Fatalf("servingCells with an unreadable SJC = %v; want the probe failure to fail discovery", err)
	}
	buckets["SJC"].failure = nil

	buckets["GRU"].objects[releasechannel.StatusObject] = membershipStatus("GRU", now.Add(-releasechannel.MaxPinAge-time.Minute))
	if _, err = servingCells(t.Context(), open, now); err == nil || !strings.Contains(err.Error(), "stale deployment scope for GRU") {
		t.Fatalf("servingCells with a stale GRU scope = %v; want the stale scope to fail discovery", err)
	}
}
