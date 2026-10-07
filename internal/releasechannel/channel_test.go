package releasechannel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/oracle/oci-go-sdk/v65/objectstorage"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

const (
	testRevision    = "0123456789abcdef0123456789abcdef01234567"
	testLineageBase = "89abcdef0123456789abcdef0123456789abcdef"
	testRunNumber   = 620
)

type anyLineage struct{}

func (anyLineage) CheckLineage(string, string, string) error { return nil }

type channelFixture struct {
	now        time.Time
	roots      trust.Keyring
	delegation trust.Envelope
	leaf       ed25519.PrivateKey
	qual       release.Qualification
	qualDigest string
	binaries   map[string]release.BinaryReceipt
}

func newChannelFixture(t *testing.T) channelFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := trust.KeyID(leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	encodedLeaf, err := trust.EncodeDelegatedPublicKey(leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := release.SignUpdateDelegation(release.BinaryUpdateDelegation{
		Schema: release.UpdateDelegationSchema, SubjectKeyID: keyID, SubjectPublicKey: encodedLeaf,
		Environment: "production", Cells: []string{"GRU", "SFO"}, Architectures: []string{"amd64", "arm64"},
		Repository: release.QualificationRepository, Workflow: release.QualificationWorkflow,
		Ref: release.LineageRef, LineageBase: testLineageBase,
	}, now.Add(-time.Minute), now.Add(7*24*time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	digests := map[string]string{}
	for _, architecture := range []string{"amd64", "arm64"} {
		sum := sha256.Sum256([]byte("binary " + architecture))
		digests[architecture] = hex.EncodeToString(sum[:])
	}
	qual := release.Qualification{
		Schema: release.QualificationSchema, Repository: release.QualificationRepository,
		SourceRevision: testRevision, SourceTree: testRevision, GoVersion: release.DefaultGoVersion,
		GoModSHA256: digests["amd64"], GoSumSHA256: digests["amd64"],
		Verification: release.QualificationCheck{Workflow: release.QualificationWorkflow, Job: release.QualificationJob,
			RunID: 4001, RunNumber: testRunNumber, Conclusion: "success"},
		Artifacts: []release.QualifiedArtifact{
			{Architecture: "amd64", Name: "terrascale-orchestrator-linux-amd64", Bytes: 13, SHA256: digests["amd64"]},
			{Architecture: "arm64", Name: "terrascale-orchestrator-linux-arm64", Bytes: 13, SHA256: digests["arm64"]},
		},
	}
	wire, err := trust.EncodePayload(qual)
	if err != nil {
		t.Fatal(err)
	}
	qualSum := sha256.Sum256(wire)
	fixture := channelFixture{now: now, roots: roots, delegation: delegation, leaf: leafPrivate, qual: qual,
		qualDigest: hex.EncodeToString(qualSum[:]), binaries: map[string]release.BinaryReceipt{}}
	for architecture, machine := range map[string]string{"amd64": "Advanced Micro Devices X86-64", "arm64": "AArch64"} {
		fixture.binaries[architecture] = release.BinaryReceipt{
			Schema: release.BinarySchema, SourceRevision: testRevision, GoVersion: release.DefaultGoVersion,
			GOOS: "linux", GOARCH: architecture, ELFMachine: machine, Static: true, Bytes: 13,
			SHA256: digests[architecture], QualificationSHA256: fixture.qualDigest,
		}
	}
	return fixture
}

func (fixture channelFixture) receipt(t *testing.T, cell, architecture string) jsontext.Value {
	t.Helper()
	envelope, err := release.SignBinaryUpdateReceipt(fixture.binaries[architecture], fixture.qual, fixture.qualDigest,
		cell, "production", anyLineage{}, fixture.delegation, fixture.roots, fixture.leaf, fixture.now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func (fixture channelFixture) channel(t *testing.T, cell string) Channel {
	t.Helper()
	delegation, err := trust.EncodeEnvelope(fixture.delegation)
	if err != nil {
		t.Fatal(err)
	}
	return Channel{Schema: ChannelSchema, Cell: cell, Environment: "production", SourceRevision: testRevision,
		RunNumber: testRunNumber, Delegation: delegation,
		Receipts: []jsontext.Value{fixture.receipt(t, cell, "amd64"), fixture.receipt(t, cell, "arm64")}}
}

func TestChannelVerifiesEveryArchitectureForItsCell(t *testing.T) {
	fixture := newChannelFixture(t)
	channel := fixture.channel(t, "GRU")
	verified, err := channel.Verify(fixture.roots, "GRU", "production", fixture.now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	for architecture, binary := range fixture.binaries {
		if verified[architecture].Receipt() != binary {
			t.Fatalf("%s verified as %+v", architecture, verified[architecture].Receipt())
		}
	}
	// The channel round-trips through its stored JSON.
	wire, err := json.Marshal(channel)
	if err != nil {
		t.Fatal(err)
	}
	var stored Channel
	if err := json.Unmarshal(wire, &stored); err != nil {
		t.Fatal(err)
	}
	if _, err := stored.Verify(fixture.roots, "GRU", "production", fixture.now); err != nil {
		t.Fatalf("stored channel: %v", err)
	}
}

func TestChannelVerifyRefusesTampering(t *testing.T) {
	fixture := newChannelFixture(t)
	otherRoot, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherRoots, err := trust.ParseKeyring(otherRoot)
	if err != nil {
		t.Fatal(err)
	}
	sfo := fixture.receipt(t, "SFO", "arm64")
	for name, test := range map[string]struct {
		edit        func(*Channel)
		roots       trust.Keyring
		cell        string
		environment string
		now         time.Time
	}{
		"another region's channel": {cell: "SFO"},
		"another environment":      {environment: "canary"},
		"unknown root":             {roots: otherRoots},
		"expired receipts":         {now: fixture.now.Add(25 * time.Hour)},
		"a receipt signed for another region": {edit: func(channel *Channel) {
			channel.Receipts[1] = sfo
		}},
		"a duplicated architecture": {edit: func(channel *Channel) {
			channel.Receipts[1] = channel.Receipts[0]
		}},
		"another revision": {edit: func(channel *Channel) {
			channel.SourceRevision = testLineageBase
		}},
		"a forged run number": {edit: func(channel *Channel) {
			channel.RunNumber++
		}},
		"no receipts": {edit: func(channel *Channel) {
			channel.Receipts = nil
		}},
		"an altered receipt": {edit: func(channel *Channel) {
			channel.Receipts[0] = bytes.Replace(channel.Receipts[0], []byte(`"payload":{`), []byte(`"payload":{"x":1,`), 1)
		}},
		"another schema": {edit: func(channel *Channel) {
			channel.Schema = "terrascale.orchestrator.release-channel.v2"
		}},
	} {
		t.Run(name, func(t *testing.T) {
			channel := fixture.channel(t, "GRU")
			if test.edit != nil {
				test.edit(&channel)
			}
			roots, cell, environment, now := fixture.roots, "GRU", "production", fixture.now
			if test.roots != nil {
				roots = test.roots
			}
			if test.cell != "" {
				cell = test.cell
			}
			if test.environment != "" {
				environment = test.environment
			}
			if !test.now.IsZero() {
				now = test.now
			}
			if _, err := channel.Verify(roots, cell, environment, now); err == nil {
				t.Fatal("tampered channel verified")
			}
		})
	}
}

// fakeBucket is an in-memory Object Storage bucket with ETag preconditions.
type fakeBucket struct {
	mu      sync.Mutex
	objects map[string][]byte
	etags   map[string]string
	version int
	// beforePut runs once, before the next conditional put is checked.
	beforePut func()
	puts      int
}

type serviceError int

func (err serviceError) Error() string          { return fmt.Sprintf("HTTP %d", int(err)) }
func (err serviceError) GetHTTPStatusCode() int { return int(err) }
func (serviceError) GetMessage() string         { return "" }
func (serviceError) GetCode() string            { return "" }
func (serviceError) GetOpcRequestID() string    { return "" }

func newFakeBucket() *fakeBucket {
	return &fakeBucket{objects: map[string][]byte{}, etags: map[string]string{}}
}

func (bucket *fakeBucket) set(name string, data []byte) {
	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	bucket.version++
	bucket.objects[name] = data
	bucket.etags[name] = fmt.Sprintf("etag-%d", bucket.version)
}

func (bucket *fakeBucket) GetObject(_ context.Context, request objectstorage.GetObjectRequest) (objectstorage.GetObjectResponse, error) {
	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	data, ok := bucket.objects[*request.ObjectName]
	if !ok {
		return objectstorage.GetObjectResponse{}, serviceError(404)
	}
	etag := bucket.etags[*request.ObjectName]
	return objectstorage.GetObjectResponse{Content: io.NopCloser(bytes.NewReader(data)), ETag: &etag}, nil
}

func (bucket *fakeBucket) PutObject(_ context.Context, request objectstorage.PutObjectRequest) (objectstorage.PutObjectResponse, error) {
	if hook := bucket.beforePut; hook != nil {
		bucket.beforePut = nil
		hook()
	}
	data, err := io.ReadAll(request.PutObjectBody)
	if err != nil {
		return objectstorage.PutObjectResponse{}, err
	}
	bucket.mu.Lock()
	name := *request.ObjectName
	etag, exists := bucket.etags[name]
	bucket.puts++
	bucket.mu.Unlock()
	if request.IfNoneMatch != nil && exists || request.IfMatch != nil && *request.IfMatch != etag {
		return objectstorage.PutObjectResponse{}, serviceError(412)
	}
	bucket.set(name, data)
	return objectstorage.PutObjectResponse{}, nil
}

func (bucket *fakeBucket) object(name string) []byte {
	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	return bucket.objects[name]
}

func storedChannel(t *testing.T, bucket *fakeBucket) Channel {
	t.Helper()
	var channel Channel
	if err := json.Unmarshal(bucket.object(ChannelObject), &channel); err != nil {
		t.Fatal(err)
	}
	return channel
}

func TestPublishMovesTheChannelOnlyForward(t *testing.T) {
	fixture := newChannelFixture(t)
	bucket := newFakeBucket()
	location := Location{Client: bucket, Namespace: "ns", Bucket: "gru-1-head"}
	ctx := context.Background()
	channel := fixture.channel(t, "GRU")
	if err := Publish(ctx, location, channel); err != nil {
		t.Fatalf("first publication: %v", err)
	}
	first := bucket.object(ChannelObject)
	if stored, found, err := ReadChannel(ctx, location); err != nil || !found {
		t.Fatalf("ReadChannel: %v", err)
	} else if _, err := stored.Verify(fixture.roots, "GRU", "production", fixture.now); err != nil {
		t.Fatalf("published channel does not verify: %v", err)
	}

	// A repeated deployment of the same run renews its receipts.
	resigned := fixture.channel(t, "GRU")
	resigned.Receipts = resigned.Receipts[:1]
	if err := Publish(ctx, location, resigned); err != nil || bytes.Equal(bucket.object(ChannelObject), first) ||
		len(storedChannel(t, bucket).Receipts) != 1 {
		t.Fatalf("same run kept stale receipts: %v", err)
	}

	older := channel
	older.RunNumber--
	if err := Publish(ctx, location, older); !errors.Is(err, ErrStale) {
		t.Fatalf("older run published: %v", err)
	}
	forked := channel
	forked.SourceRevision = testLineageBase
	if err := Publish(ctx, location, forked); !errors.Is(err, ErrInvalid) {
		t.Fatalf("another revision under the same run published: %v", err)
	}

	// A concurrent writer between the read and the conditional write makes
	// the publisher read again; it then replaces only an older run.
	newer := channel
	newer.RunNumber += 2
	bucket.beforePut = func() {
		concurrent := channel
		concurrent.RunNumber++
		wire, _ := json.Marshal(concurrent)
		bucket.set(ChannelObject, wire)
	}
	if err := Publish(ctx, location, newer); err != nil || storedChannel(t, bucket).RunNumber != newer.RunNumber {
		t.Fatalf("newer run after a concurrent write: %v", err)
	}
	bucket.beforePut = func() {
		concurrent := channel
		concurrent.RunNumber += 3
		wire, _ := json.Marshal(concurrent)
		bucket.set(ChannelObject, wire)
	}
	next := channel
	next.RunNumber += 3
	next.SourceRevision = testLineageBase
	if err := Publish(ctx, location, next); !errors.Is(err, ErrInvalid) {
		t.Fatalf("lost race overwrote the winner: %v", err)
	}

	corrupt := newFakeBucket()
	corrupt.set(ChannelObject, []byte("{"))
	if err := Publish(ctx, Location{Client: corrupt, Namespace: "ns", Bucket: "gru-1-head"}, channel); err == nil {
		t.Fatal("published over an unreadable channel")
	}
}

func TestAwaitFollowsTheRegionStatus(t *testing.T) {
	channel := Channel{Cell: "GRU", SourceRevision: testRevision, RunNumber: testRunNumber}
	status := func(run int64, state State, reason string) []byte {
		wire, _ := json.Marshal(Status{Schema: StatusSchema, Cell: "GRU", SourceRevision: testRevision,
			RunNumber: run, State: state, Reason: reason, UpdatedAt: time.Now()})
		return wire
	}
	for name, test := range map[string]struct {
		steps   [][]byte
		wantErr bool
		want    string
	}{
		"completes after rolling": {steps: [][]byte{nil, status(testRunNumber-1, StateComplete, ""),
			status(testRunNumber, StateRolling, "controllers wave 1/3"), status(testRunNumber, StateComplete, "")},
			want: "GRU rolling controllers wave 1/3"},
		"rolled back":           {steps: [][]byte{status(testRunNumber, StateFailed, "hosts wave 2\x1b[31m\u202e\u2028::stop-commands::")}, wantErr: true, want: "hosts wave 2 [31m  ::stop-commands::"},
		"moved past the run":    {steps: [][]byte{status(testRunNumber+1, StateRolling, "")}, wantErr: true},
		"never reports":         {steps: [][]byte{status(testRunNumber, StateRolling, "")}, wantErr: true},
		"unreadable then done":  {steps: [][]byte{[]byte("{"), status(testRunNumber, StateComplete, "")}, want: "status read failed"},
		"another cell's status": {steps: [][]byte{bytes.Replace(status(testRunNumber, StateComplete, ""), []byte(`"GRU"`), []byte(`"SFO"`), 1)}, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			bucket := newFakeBucket()
			location := Location{Client: bucket, Namespace: "ns", Bucket: "gru-1-head"}
			step := 0
			// The fake advances one step per poll.
			advance := func() {
				if step < len(test.steps) {
					if test.steps[step] != nil {
						bucket.set(StatusObject, test.steps[step])
					}
					step++
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				ticker := time.NewTicker(5 * time.Millisecond)
				defer ticker.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
						advance()
					}
				}
			}()
			var progress strings.Builder
			err := Await(ctx, location, channel, time.Millisecond, time.Now().Add(500*time.Millisecond), &syncWriter{w: &progress})
			if test.wantErr != (err != nil) || err != nil && !errors.Is(err, ErrFailed) {
				t.Fatalf("Await = %v; progress:\n%s", err, progress.String())
			}
			if text := progress.String() + fmt.Sprint(err); !strings.Contains(text, test.want) {
				t.Fatalf("output %q lacks %q", text, test.want)
			}
		})
	}
}

type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (writer *syncWriter) Write(data []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return writer.w.Write(data)
}

func TestBucketNameIsTheRegionHeadBucket(t *testing.T) {
	if name, err := BucketName("GRU"); err != nil || name != "gru-1-head" {
		t.Fatalf("BucketName(GRU) = %q, %v", name, err)
	}
	if _, err := BucketName("gru"); err == nil {
		t.Fatal("BucketName accepted a lower-case cell")
	}
}

func TestClipKeepsOneBoundedLine(t *testing.T) {
	long := Clip(strings.Repeat("é", maxReason+10))
	if !utf8.ValidString(long) || utf8.RuneCountInString(long) != maxReason+3 || !strings.HasSuffix(long, "...") {
		t.Fatalf("Clip(long) = %d runes", utf8.RuneCountInString(long))
	}
	if got := Clip("a\nb\u0085c⁦d"); got != "a b c d" {
		t.Fatalf("clip = %q", got)
	}
}

func TestReleasePinValidationAndStatusBounds(t *testing.T) {
	for _, pins := range []*ReleasePins{nil, {Rollback: []string{"short"}}, {KnownBad: []string{strings.Repeat("B", 64)}}, {KnownBad: []string{strings.Repeat("z", 64)}}} {
		if err := pins.Validate(); err == nil {
			t.Fatalf("accepted invalid pins: %+v", pins)
		}
	}
	bucket := newFakeBucket()
	location := Location{Client: bucket, Namespace: "ns", Bucket: "gru-1-head"}
	pins := &ReleasePins{KnownBad: make([]string, 1200)}
	for i := range pins.KnownBad {
		pins.KnownBad[i] = fmt.Sprintf("%064x", i)
	}
	if err := WriteStatus(t.Context(), location, Status{Cell: "GRU", Pins: pins}); err != nil {
		t.Fatal(err)
	}
	status, found, err := ReadStatus(t.Context(), location)
	if err != nil || !found || !status.Pins.Equal(pins) {
		t.Fatalf("large pin inventory lost: %+v %v", status.Pins, err)
	}
	if err := WriteServiceStatus(t.Context(), location, ServiceStatus{Cell: "GRU", Role: "terrabase", Pins: pins}); err != nil {
		t.Fatal(err)
	}
	service, found, err := ReadServiceStatus(t.Context(), location, "terrabase")
	if err != nil || !found || !service.Pins.Equal(pins) {
		t.Fatalf("large service pin inventory lost: %+v %v", service.Pins, err)
	}
	before := bucket.puts
	if err := location.write(t.Context(), StatusObject, make([]byte, maxStatusBytes+1)); !errors.Is(err, ErrInvalid) || bucket.puts != before {
		t.Fatalf("oversized status write: %v, puts %d -> %d", err, before, bucket.puts)
	}
}
