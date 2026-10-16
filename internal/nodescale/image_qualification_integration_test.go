package nodescale

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// These fixture statements are signed test evidence, never production qualification.
func TestImageQualificationSignedEvidenceHTTP(t *testing.T) {
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
	now := time.Now().UTC().Truncate(time.Second)
	evidence := []byte("source-only fixture of retained qualification evidence\n")
	evidenceSum := sha256.Sum256(evidence)
	evidenceDigest := hex.EncodeToString(evidenceSum[:])
	image := release.ImageReceipt{Schema: release.ImageSchema, SourceRevision: strings.Repeat("a", 40), GoVersion: release.DefaultGoVersion,
		Architecture: "amd64", BinaryBytes: 13, BinarySHA256: strings.Repeat("b", 64), QualificationSHA256: strings.Repeat("c", 64),
		BaseImageOCID: "ocid1.image.oc1.sa-saopaulo-1.base", BaseImageRegion: "GRU", BaseImageSHA256: strings.Repeat("d", 64),
		KernelRelease: "6.8.0", KernelSHA256: strings.Repeat("e", 64), ImageFormat: "qcow2", ImageBytes: 4096,
		ImageSHA256: strings.Repeat("f", 64), OCIImageOCID: "ocid1.image.oc1.sa-saopaulo-1.qualified", OCIRegion: "GRU"}
	wire := func(envelope trust.Envelope) []byte {
		t.Helper()
		encoded, err := trust.EncodeEnvelope(envelope)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	production := func(role, imageDigest string, issued, expires time.Time) release.ProductionProof {
		t.Helper()
		qualification := release.ProductionQualification{Schema: release.ProductionQualificationSchema,
			Candidate: release.ProductionExpectation{SourceRevision: image.SourceRevision, ArtifactSHA256: imageDigest,
				QualificationSHA256: image.QualificationSHA256, Cell: "GRU", Environment: "production", Runtime: release.ProductionRuntime, Architecture: "amd64", Role: role}}
		for _, gate := range []string{"runtime-ha", "workload-safety"} {
			qualification.Evidence = append(qualification.Evidence, release.ProductionGateEvidence{Gate: gate,
				SHA256: evidenceDigest, Bytes: int64(len(evidence)), CompletedAt: issued})
		}
		payload, err := trust.EncodePayload(qualification)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := trust.Sign(payload, release.ProductionQualificationScope(qualification.Candidate), issued, expires, rootPrivate)
		if err != nil {
			t.Fatal(err)
		}
		return release.ProductionProof{Qualification: wire(envelope)}
	}
	imageProof := production("orchestrator", image.ImageSHA256, now.Add(-time.Hour), now.Add(time.Hour))
	image.Production = &imageProof
	leafID, err := trust.KeyID(leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := trust.EncodeDelegatedPublicKey(leafPublic)
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: leafID, SubjectPublicKey: leafKey,
		Capabilities: []trust.Capability{{Domain: release.ImageDomain, DeploymentID: entityid.Derive("build", image.SourceRevision), Cell: "GRU", Environment: "production", Role: "oci-image", Slots: []string{image.OCIImageOCID}, Actions: []string{"sign"}}}},
		now.Add(-2*time.Hour), now.Add(45*time.Minute), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct {
		name, role, badScope string
		missingProduction    bool
		missingRole          bool
		expiredReceipt       bool
		futureReceipt        bool
		wrongRoleImage       bool
		wrongRole            bool
		expiredRole          bool
		corruptEvidence      bool
		missingEvidence      bool
	}{
		{name: "manager consumes signed final disk proof", role: RoleManager},
		{name: "container requires exact image worker proof", role: RoleContainer},
		{name: "function requires exact image worker proof", role: RoleWasm},
		{name: "wrong image OCID pending", role: RoleManager, badScope: "image"},
		{name: "wrong native architecture pending", role: RoleManager, badScope: "architecture"},
		{name: "wrong cell pending", role: RoleManager, badScope: "cell"},
		{name: "wrong environment pending", role: RoleManager, badScope: "environment"},
		{name: "legacy image has no production authority", role: RoleManager, missingProduction: true},
		{name: "orchestrator proof cannot qualify worker", role: RoleContainer, missingRole: true},
		{name: "expired image pending without skew", role: RoleManager, expiredReceipt: true},
		{name: "future image pending without skew", role: RoleManager, futureReceipt: true},
		{name: "worker proof pins other disk", role: RoleContainer, wrongRoleImage: true},
		{name: "container cannot use function proof", role: RoleContainer, wrongRole: true},
		{name: "expired worker proof pending", role: RoleWasm, expiredRole: true},
		{name: "corrupted retained evidence pending", role: RoleContainer, corruptEvidence: true},
		{name: "missing retained evidence pending", role: RoleManager, missingEvidence: true},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodGet || request.URL.Path != "/objects/"+evidenceDigest || scenario.missingEvidence {
					http.NotFound(w, request)
					return
				}
				if scenario.corruptEvidence {
					_, _ = io.WriteString(w, "changed fixture evidence")
					return
				}
				_, _ = w.Write(evidence)
			}))
			t.Cleanup(server.Close)
			openEvidence := func(ctx context.Context, digest string) (io.ReadCloser, error) {
				request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/objects/"+digest, nil)
				if err != nil {
					return nil, err
				}
				response, err := server.Client().Do(request)
				if err != nil {
					return nil, err
				}
				if response.StatusCode != http.StatusOK {
					_ = response.Body.Close()
					return nil, errors.New("retained evidence object is absent")
				}
				return response.Body, nil
			}
			receipt := image
			if scenario.missingProduction {
				receipt.Production = nil
			}
			issued, expires := now.Add(-time.Minute), now.Add(40*time.Minute)
			if scenario.expiredReceipt {
				issued, expires = now.Add(-time.Hour), now.Add(-time.Second)
			}
			if scenario.futureReceipt {
				issued = now.Add(10 * time.Second)
			}
			payload, err := trust.EncodePayload(receipt)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := trust.Sign(payload, release.ImageScope(receipt, "production"), issued, expires, leafPrivate)
			if err != nil {
				t.Fatal(err)
			}
			input := ImageQualification{Receipt: wire(envelope), Delegation: wire(delegation), Role: scenario.role,
				Expected: release.ImageExpectation{Environment: "production", LogicalRegion: "GRU", OCIImageOCID: image.OCIImageOCID, Architecture: "amd64"}}
			wantExpiry := expires
			if scenario.role != RoleManager && !scenario.missingRole {
				role, disk, deadline := scenario.role, image.ImageSHA256, now.Add(30*time.Minute)
				if scenario.wrongRole {
					role = RoleWasm
				}
				if scenario.wrongRoleImage {
					disk = strings.Repeat("a", 64)
				}
				if scenario.expiredRole {
					deadline = now.Add(-time.Second)
				}
				proof := production(role, disk, now.Add(-time.Hour), deadline)
				input.RoleProduction = &proof
				wantExpiry = deadline
			}
			switch scenario.badScope {
			case "image":
				input.Expected.OCIImageOCID = "ocid1.image.oc1.sa-saopaulo-1.other"
			case "architecture":
				input.Expected.Architecture = "arm64"
			case "cell":
				input.Expected.LogicalRegion = "SFO"
			case "environment":
				input.Expected.Environment = "canary"
			}
			qualified, deadline, err := QualifyImage(t.Context(), input, roots, openEvidence, now)
			failure := scenario.badScope != "" || scenario.missingProduction || scenario.missingRole || scenario.expiredReceipt || scenario.futureReceipt || scenario.wrongRoleImage || scenario.wrongRole || scenario.expiredRole || scenario.corruptEvidence || scenario.missingEvidence
			if failure {
				if !errors.Is(err, ErrCapacityPending) || qualified != (QualifiedImage{}) || !deadline.IsZero() {
					t.Fatalf("qualified=%+v deadline=%s err=%v; want concrete pending without usable proof", qualified, deadline, err)
				}
				return
			}
			if err != nil || qualified.ID != image.OCIImageOCID || qualified.Architecture != "amd64" || qualified.Role != scenario.role || qualified.RuntimeManifestDigest != image.ImageSHA256 || !deadline.Equal(wantExpiry) {
				t.Fatalf("qualified=%+v deadline=%s err=%v; want pinned disk role=%s expiry=%s", qualified, deadline, err, scenario.role, wantExpiry)
			}
		})
	}
}
