package region

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/common"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

type originalMaterialIAMDispatch struct {
	body    []byte
	token   string
	pending PendingFoundationCreate
}

type originalMaterialIAMSDKFixture struct {
	*originalPublicationSDKFixture
	materialMu  sync.Mutex
	fault       string
	faulted     bool
	posts       []originalMaterialIAMDispatch
	groupPosts  []originalMaterialIAMDispatch
	groupRows   map[string]map[string]any
	rows        map[string]map[string]any
	gets        map[string]int
	journalPuts int
	joinHTTP    http.Handler
}

func newOriginalMaterialIAMSDKFixture(t *testing.T, fault string) *originalMaterialIAMSDKFixture {
	t.Helper()
	// Preserve pinned loopback TLS instead of the OCI SDK's proxy transport clone.
	t.Setenv(common.UsingExpectHeaderEnvVar, "false")
	return originalMaterialIAMSDKFixtureFor(t, newOriginalActorReadsSDKFixture(t, "", 0), fault)
}

func originalMaterialIAMSDKFixtureFor(t *testing.T, reads *originalActorReadsSDKFixture, fault string) *originalMaterialIAMSDKFixture {
	t.Helper()
	if reads.prepared.Grant.OriginalMaterialPublicationIAM == nil {
		t.Fatal("prospective preparation omitted material IAM")
	}
	admission := originalAdmissionReadsSDKFixtureFor(t, reads, "")
	publication := originalPublicationSDKFixtureFor(t, admission, "")
	f := &originalMaterialIAMSDKFixture{originalPublicationSDKFixture: publication, fault: fault, rows: map[string]map[string]any{}, groupRows: map[string]map[string]any{}, gets: map[string]int{}}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(server.Close)
	listener, ok := server.Listener.Addr().(*net.TCPAddr)
	if !ok || !listener.IP.IsLoopback() || listener.Port == 0 {
		t.Fatal("material IAM requires literal loopback TLS")
	}
	previous := http.DefaultTransport
	transport := previous.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("material IAM fixture refuses plaintext and proxies")
	}
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("unexpected network %q", network)
		}
		return (&tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, "tcp", listener.String())
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections() })
	return f
}

func originalMaterialIAMSnapshot(t *testing.T, cloud *provisionCloud) []byte {
	t.Helper()
	cloud.mu.Lock()
	defer cloud.mu.Unlock()
	entries, err := os.ReadDir(cloud.directory)
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		wire, err := os.ReadFile(filepath.Join(cloud.directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files[entry.Name()] = wire
	}
	wire, err := json.Marshal(files, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func (f *originalMaterialIAMSDKFixture) expectedMaterialPolicy(t *testing.T, record FoundationRecord, index int) map[string]any {
	t.Helper()
	regional := record.OriginalFoundationCompartments.Regions[index]
	entry := regional.MaterialPublicationIAM
	if entry.Recipe.Purpose == originalMaterialIAMPurposeV3 || entry.Recipe.Purpose == originalMaterialIAMPurposeV4 {
		assertOriginalMaterialV3Policy(t, record, index)
		return map[string]any{"compartmentId": f.approval.TenancyID, "name": "ts-original-material-iam-" + entry.IdentitySHA256[:32], "description": "Prospectively authorized finite original startup and material publication", "statements": entry.Request.Statements, "freeformTags": map[string]any{}, "definedTags": map[string]any{}}
	}
	cfg := f.prepared.Grant.Regions[index].BootstrapMaterial.Config
	names, err := bootstrapmaterial.OriginalPublicationSecretNames(cfg)
	if err != nil || len(names) != 33 {
		t.Fatal("actual material naming roster unavailable", err)
	}
	principal := fmt.Sprintf("request.principal.type='instance', request.principal.id='%s'", regional.Actor.Provenance.ResourceID)
	control := originalCompartmentID(regional.Compartments[0])
	vault := originalVaultID(regional.Vault.Vault.OriginalFoundationKMSCreate)
	key := originalVaultID(regional.Vault.Key.OriginalFoundationKMSCreate)
	conditions := make([]string, len(names))
	for i, name := range names {
		conditions[i] = "target.secret.name='" + name + "'"
	}
	statement := func(verb, resource, operation, permission, extra string) string {
		return fmt.Sprintf("Allow any-user to %s %s in compartment id %s where all {%s, request.operation='%s', request.permission='%s'%s}", verb, resource, control, principal, operation, permission, extra)
	}
	finite := fmt.Sprintf(", target.vault.id='%s', any {%s}", vault, strings.Join(conditions, ", "))
	statements := []string{
		statement("inspect", "secrets", "ListSecrets", "SECRET_INSPECT", ""),
		statement("manage", "secrets", "CreateSecret", "SECRET_CREATE", finite),
		statement("read", "secrets", "GetSecret", "SECRET_READ", finite),
		statement("read", "secret-bundles", "GetSecretBundle", "SECRET_BUNDLE_READ", finite),
		statement("use", "vaults", "CreateSecret", "VAULT_CREATE_SECRET", fmt.Sprintf(", target.vault.id='%s'", vault)),
		statement("use", "keys", "CreateSecret", "KEY_ENCRYPT", fmt.Sprintf(", target.key.id='%s'", key)),
		statement("use", "keys", "CreateSecret", "KEY_DECRYPT", fmt.Sprintf(", target.key.id='%s'", key)),
	}
	if entry.Recipe.Purpose == "original-material-publication-iam/v2" {
		statements = append(statements, statement("read", "policies", "GetPolicy", "POLICY_READ", ""))
	}
	return map[string]any{"compartmentId": control, "name": "ts-original-material-iam-" + entry.IdentitySHA256[:32], "description": "Prospectively authorized finite original material publication", "statements": statements, "freeformTags": map[string]any{}, "definedTags": map[string]any{}}
}

func (f *originalMaterialIAMSDKFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.materialMu.Lock()
	joinHTTP := f.joinHTTP
	f.materialMu.Unlock()
	if joinHTTP != nil && (strings.HasPrefix(r.URL.Path, "/20180608/secrets") || r.URL.Path == "/20190301/secretbundles/actions/getByName") {
		joinHTTP.ServeHTTP(w, r)
		return
	}
	f.materialMu.Lock()
	defer f.materialMu.Unlock()
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
		f.cloud.test.Error("material IAM request lacks actual SDK signing")
	}
	// Only journal writes and IAM effects are checked against the journal.
	var record FoundationRecord
	if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/o/"+foundationObjectPrefix+"GRU.json") || strings.Contains(r.URL.Path, "/dynamicGroups") || strings.Contains(r.URL.Path, "/policies") {
		record = f.record(f.cloud.test)
	}
	if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/o/"+foundationObjectPrefix+"GRU.json") {
		wire, err := io.ReadAll(io.LimitReader(r.Body, foundationJournalLimit+1))
		var next FoundationRecord
		if err != nil || json.Unmarshal(wire, &next) != nil {
			f.cloud.test.Error("invalid material checkpoint")
			originalCompartmentFailure(w, 400, "InvalidParameter")
			return
		}
		f.journalPuts++
		phase := ""
		for index, regional := range next.OriginalFoundationCompartments.Regions {
			before, after := record.OriginalFoundationCompartments.Regions[index].MaterialPublicationIAM, regional.MaterialPublicationIAM
			if after == nil {
				continue
			}
			if before == nil {
				phase = "scope checkpoint"
			} else if before.Pending == nil && after.Pending != nil {
				phase = "reservation checkpoint"
			} else if before.Provenance == nil && after.Provenance != nil {
				phase = "receipt checkpoint"
			} else if before.VerifiedAt.IsZero() && !after.VerifiedAt.IsZero() {
				phase = "completion checkpoint"
			}
			if before != nil && before.PeerDynamicGroup != nil && after.PeerDynamicGroup != nil {
				old, current := before.PeerDynamicGroup, after.PeerDynamicGroup
				if old.Pending == nil && current.Pending != nil {
					phase = "group reservation checkpoint"
				}
				if old.Provenance == nil && current.Provenance != nil {
					phase = "group receipt checkpoint"
				}
				if old.VerifiedAt.IsZero() && !current.VerifiedAt.IsZero() {
					phase = "group completion checkpoint"
				}
			}
		}
		if phase != "" && !f.faulted && (f.fault == phase || f.fault == "lost "+phase) {
			f.faulted = true
			if strings.HasPrefix(f.fault, "lost ") {
				r.Body = io.NopCloser(bytes.NewReader(wire))
				recorder := httptest.NewRecorder()
				f.originalPublicationSDKFixture.serveHTTP(recorder, r)
				if recorder.Code >= 300 {
					f.cloud.test.Error("lost material acknowledgement did not follow accepted CAS")
				}
			}
			originalCompartmentFailure(w, 503, "InternalError")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(wire))
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) >= 2 && parts[1] == "dynamicGroups" {
		if r.Host != "identity.sa-saopaulo-1.oci.oraclecloud.com" {
			f.cloud.test.Error("peer group escaped HOME IAM")
		}
		if r.Method == http.MethodPost && len(parts) == 2 {
			body, canonical, err := originalNetworkBody(r)
			if err != nil {
				f.cloud.test.Fatal(err)
			}
			index := slices.IndexFunc(record.OriginalFoundationCompartments.Regions[:], func(regional OriginalFoundationCompartmentRegion) bool {
				return regional.MaterialPublicationIAM != nil && regional.MaterialPublicationIAM.PeerDynamicGroup != nil && deref(regional.MaterialPublicationIAM.PeerDynamicGroup.Request.Name) == body["name"]
			})
			if index < 0 {
				f.cloud.test.Error("group lacks a retained scope")
				originalCompartmentFailure(w, 400, "InvalidParameter")
				return
			}
			regional := record.OriginalFoundationCompartments.Regions[index]
			entry := regional.MaterialPublicationIAM
			group := entry.PeerDynamicGroup
			want := map[string]any{"compartmentId": f.approval.TenancyID, "name": "ts-original-peer-" + entry.IdentitySHA256[:32], "description": "Original regional controllers admitted by exact control compartment", "matchingRule": fmt.Sprintf("ALL {instance.compartment.id='%s'}", regional.Actor.ControlCompartmentID), "freeformTags": map[string]any{}, "definedTags": map[string]any{}}
			// The peer group identity digests the retained SDK details, not the re-sorted wire.
			retained, err := json.Marshal(group.Request, json.Deterministic(true))
			if err != nil || group.Pending == nil || group.Provenance != nil || entry.Pending != nil || group.Pending.Request.RequestDigest != digestSource(retained) || group.Pending.Request.RetryToken != r.Header.Get("opc-retry-token") || !sameOriginalSourceValue(body, want) {
				f.cloud.test.Error("group effect escaped acknowledged exact scope")
				originalCompartmentFailure(w, 400, "InvalidParameter")
				return
			}
			f.groupPosts = append(f.groupPosts, originalMaterialIAMDispatch{body: bytes.Clone(canonical), token: r.Header.Get("opc-retry-token"), pending: *group.Pending})
			id := fmt.Sprintf("ocid1.dynamicgroup.oc1..originalpeer%d", index+1)
			if f.fault == "group duplicate id" {
				id = "ocid1.dynamicgroup.oc1..originalpeer1"
			}
			row := maps.Clone(body)
			row["id"], row["lifecycleState"] = id, "ACTIVE"
			f.groupRows[id] = row
			if f.fault == "lost group create response" && !f.faulted {
				f.faulted = true
				originalCompartmentFailure(w, 503, "InternalError")
				return
			}
			json.MarshalWrite(w, row)
			return
		}
		if r.Method == http.MethodGet && len(parts) == 3 {
			if row := f.groupRows[parts[2]]; row != nil {
				index := slices.IndexFunc(record.OriginalFoundationCompartments.Regions[:], func(regional OriginalFoundationCompartmentRegion) bool {
					return regional.MaterialPublicationIAM != nil && regional.MaterialPublicationIAM.PeerDynamicGroup != nil && regional.MaterialPublicationIAM.PeerDynamicGroup.Provenance != nil && regional.MaterialPublicationIAM.PeerDynamicGroup.Provenance.ResourceID == parts[2]
				})
				if index < 0 {
					f.cloud.test.Error("group read before provider receipt")
				}
				f.gets[parts[2]]++
				row = maps.Clone(row)
				if f.fault == "group readback conflict" {
					row["matchingRule"] = "ALL {instance.compartment.id='ocid1.compartment.oc1..foreign'}"
				}
				wire, err := json.Marshal(row, json.Deterministic(true))
				if err != nil {
					f.cloud.test.Fatal(err)
				}
				etag := digestSource(wire)
				if f.fault == "group ETag changed" {
					etag = "changed-group-etag"
				}
				if f.fault != "group ETag missing" {
					w.Header().Set("etag", etag)
				}
				w.Write(wire)
				return
			}
		}
	}
	if len(parts) >= 2 && parts[1] == "policies" {
		if r.Host != "identity.sa-saopaulo-1.oci.oraclecloud.com" {
			f.cloud.test.Error("material policy escaped HOME IAM")
		}
		if r.Method == http.MethodPost && len(parts) == 2 {
			body, canonical, err := originalNetworkBody(r)
			if err != nil {
				f.cloud.test.Error(err)
				originalCompartmentFailure(w, 400, "InvalidParameter")
				return
			}
			if name, _ := body["name"].(string); strings.HasPrefix(name, "ts-original-material-iam-") {
				index := slices.IndexFunc(record.OriginalFoundationCompartments.Regions[:], func(regional OriginalFoundationCompartmentRegion) bool {
					return regional.MaterialPublicationIAM != nil && deref(regional.MaterialPublicationIAM.Request.Name) == name
				})
				if index < 0 || completeOriginalMaterialIAMPrerequisites(record) != nil {
					f.cloud.test.Error("material effect lacks genuine completed prerequisites")
					originalCompartmentFailure(w, 400, "InvalidParameter")
					return
				}
				entry := record.OriginalFoundationCompartments.Regions[index].MaterialPublicationIAM
				if (entry.Recipe.Purpose == originalMaterialIAMPurposeV3 || entry.Recipe.Purpose == originalMaterialIAMPurposeV4) && (entry.PeerDynamicGroup == nil || entry.PeerDynamicGroup.VerifiedAt.IsZero() || entry.PeerDynamicGroup.Provenance == nil || f.gets[entry.PeerDynamicGroup.Provenance.ResourceID] == 0) {
					f.cloud.test.Error("policy preceded acknowledged actual group readback")
					originalCompartmentFailure(w, 400, "InvalidParameter")
					return
				}
				if entry.Pending == nil || entry.Provenance != nil || entry.Pending.Request.RequestDigest != digestSource(canonical) || entry.Pending.Request.RetryToken != r.Header.Get("opc-retry-token") || !sameOriginalSourceValue(body, f.expectedMaterialPolicy(f.cloud.test, record, index)) {
					f.cloud.test.Error("material create escaped signed finite policy or acknowledged request")
					originalCompartmentFailure(w, 400, "InvalidParameter")
					return
				}
				wire, err := os.ReadFile(f.cloud.objectPath("gru-1-head/" + homeIAMObject))
				var lease homeIAMRecord
				if err != nil || json.Unmarshal(wire, &lease) != nil || !lease.ReleasedAt.IsZero() || !time.Now().Before(lease.ExpiresAt) || lease.OperatorID != record.OriginalFoundationCompartments.UserID {
					f.cloud.test.Error("material effect lacks actual live HomeWrite")
				}
				f.posts = append(f.posts, originalMaterialIAMDispatch{body: bytes.Clone(canonical), token: r.Header.Get("opc-retry-token"), pending: *entry.Pending})
				if f.fault == "create refused" {
					originalCompartmentFailure(w, 409, "Conflict")
					return
				}
				id := fmt.Sprintf("ocid1.policy.oc1..originalmaterial%d", index+1)
				row := maps.Clone(body)
				row["id"], row["lifecycleState"] = id, "ACTIVE"
				if old := f.rows[id]; old != nil && !sameOriginalSourceValue(old, row) {
					f.cloud.test.Error("retry changed material policy or created another identity")
				}
				f.rows[id] = row
				if f.fault == "lost create response" && !f.faulted {
					f.faulted = true
					originalCompartmentFailure(w, 503, "InternalError")
					return
				}
				json.MarshalWrite(w, row)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(canonical))
		}
		if r.Method == http.MethodGet && len(parts) == 3 {
			if row := f.rows[parts[2]]; row != nil {
				index := slices.IndexFunc(record.OriginalFoundationCompartments.Regions[:], func(regional OriginalFoundationCompartmentRegion) bool {
					return regional.MaterialPublicationIAM != nil && regional.MaterialPublicationIAM.Provenance != nil && regional.MaterialPublicationIAM.Provenance.ResourceID == parts[2]
				})
				if index < 0 {
					f.cloud.test.Error("material policy read preceded actual durable provider ID")
				}
				f.gets[parts[2]]++
				if f.fault == "readback missing" {
					originalCompartmentFailure(w, 404, "NotAuthorizedOrNotFound")
					return
				}
				if f.fault == "readback unavailable" {
					originalCompartmentFailure(w, 503, "InternalError")
					return
				}
				row = maps.Clone(row)
				if f.fault == "readback conflict" {
					row["statements"] = []string{"Allow any-user to manage all-resources in tenancy"}
				}
				if f.fault == "readback compartment" {
					row["compartmentId"] = "ocid1.compartment.oc1..foreign"
				}
				if f.fault == "readback pending deletion" {
					row["lifecycleState"] = "DELETING"
				}
				wire, err := json.Marshal(row, json.Deterministic(true))
				if err != nil {
					f.cloud.test.Error(err)
				}
				etag := digestSource(wire)
				if f.fault == "readback ETag changed" {
					etag = "different-current-etag"
				}
				if f.fault != "readback ETag missing" {
					w.Header().Set("etag", etag)
				}
				w.Write(wire)
				return
			}
		}
	}
	f.originalPublicationSDKFixture.serveHTTP(w, r)
}

func (f *originalMaterialIAMSDKFixture) assertMaterialIAM(t *testing.T) {
	t.Helper()
	f.assertPublished(t)
	record := f.record(t)
	if record.Stage != "original-foundation" || f.cloud.hasAnchor() || len(f.rows) != 3 {
		t.Fatal("material IAM fabricated ordinary startup or omitted policies")
	}
	for index, regional := range record.OriginalFoundationCompartments.Regions {
		entry := regional.MaterialPublicationIAM
		if entry != nil && (entry.Recipe.Purpose == originalMaterialIAMPurposeV3 || entry.Recipe.Purpose == originalMaterialIAMPurposeV4) {
			group := entry.PeerDynamicGroup
			if group == nil || group.Pending == nil || group.Provenance == nil || group.VerifiedAt.IsZero() || group.ETag == "" || group.ReadbackSHA256 == "" || group.HoldReason != "" || f.gets[group.Provenance.ResourceID] == 0 {
				t.Fatal("v3 lacks independent actual peer group readback")
			}
		}
		if entry == nil || entry.Pending == nil || entry.Provenance == nil || entry.PolicyETag == "" || entry.ReadbackSHA256 == "" || entry.VerifiedAt.IsZero() || entry.HoldReason != "" || f.gets[entry.Provenance.ResourceID] == 0 {
			t.Fatal("material IAM lacks acknowledged policy and actual independent ETag readback")
		}
		expected := f.expectedMaterialPolicy(t, record, index)
		expected["id"], expected["lifecycleState"] = entry.Provenance.ResourceID, "ACTIVE"
		if !sameOriginalSourceValue(f.rows[entry.Provenance.ResourceID], expected) {
			t.Fatal("retained material policy differs from exact finite actual instance and regional Vault target")
		}
	}
}

func assertOriginalMaterialV3Policy(t *testing.T, record FoundationRecord, index int) {
	t.Helper()
	entry := record.OriginalFoundationCompartments.Regions[index].MaterialPublicationIAM
	if entry.Startup == nil || entry.PeerDynamicGroup == nil || len(entry.Request.Statements) == 0 || len(entry.Request.Statements) > 50 || deref(entry.Request.CompartmentId) != entry.Recipe.TenancyID {
		t.Fatal("v3 policy lacks deployable root startup scope")
	}
	allowed := []string{"GetPolicy", "GetDynamicGroup", "GetCompartment", "GetNamespace", "GetBucket", "GetRetentionRule", "GetVault", "GetKey", "ListSecrets", "CreateSecret", "GetSecret", "GetSecretBundle", "GetSecretBundleByName", "GetVcn", "GetSubnet", "GetNetworkSecurityGroup", "LaunchInstance", "GetImage", "GetInstance", "ListVnicAttachments", "GetBootVolume", "ListBootVolumeAttachments", "GetVnic", "GetObject", "PutObject"}
	actor := fmt.Sprintf("request.principal.type='instance', request.principal.id='%s'", entry.ActorID)
	peer := "Allow dynamic-group " + deref(entry.PeerDynamicGroup.Request.Name) + " "
	actorWrites := map[string]string{}
	peerWrites := ""
	for _, statement := range entry.Request.Statements {
		if strings.Contains(statement, "target.policy.id") || strings.Contains(statement, "request.principal.compartment.id") || strings.Contains(statement, "target.instance.id") || strings.Contains(statement, "target.subnet.id") || strings.Contains(statement, "target.vnic.id") {
			t.Fatal("unsupported selector in actual SDK policy", statement)
		}
		if !strings.Contains(statement, actor) && !strings.HasPrefix(statement, peer) {
			t.Fatal("policy escaped exact actor or proven per-cell group", statement)
		}
		for _, suffix := range strings.Split(statement, "request.operation='")[1:] {
			operation, _, ok := strings.Cut(suffix, "'")
			if !ok || !slices.Contains(allowed, operation) {
				t.Fatal("operation escaped finite signed startup roster", operation)
			}
		}
		if strings.Contains(statement, "request.operation='LaunchInstance'") && !strings.Contains(statement, actor) {
			t.Fatal("peer group gained founder launch authority")
		}
		if strings.HasPrefix(statement, peer) && strings.Contains(statement, "secret-bundles") && !strings.Contains(statement, "target.secret.name != /ts-bootstrap-source-*/") && !(entry.Recipe.Purpose == originalMaterialIAMPurposeV4 && strings.Contains(statement, "target.secret.name='"+entry.Recipe.RuntimeJoinSecretName+"'") && strings.Contains(statement, "target.vault.id='"+entry.Target.VaultOCID+"'")) {
			t.Fatal("peer bundle scope admitted private source escrow")
		}
		for _, branch := range strings.Split(statement, "all {request.operation='")[1:] {
			if !strings.HasPrefix(branch, "PutObject'") {
				continue
			}
			permission := "OBJECT_CREATE"
			if strings.Contains(branch, "request.permission='OBJECT_OVERWRITE'") {
				permission = "OBJECT_OVERWRITE"
			}
			if strings.HasPrefix(statement, peer) {
				peerWrites += branch
				if !strings.Contains(branch, "request.permission='OBJECT_CREATE'") || strings.Contains(branch, "request.permission='OBJECT_OVERWRITE'") || !strings.Contains(branch, "target.bucket.name='"+entry.Startup.Producer.Home.HeadBucket+"'") {
					t.Fatal("peer gained private ledger or overwrite authority", branch)
				}
				selectors := strings.Split(branch, "target.object.name=")[1:]
				if len(selectors) != 3 {
					t.Fatal("peer writes escaped the exact3 accepted-install leaves", branch)
				}
				for _, selector := range selectors {
					name, _, ok := strings.Cut(strings.TrimPrefix(selector, "'"), "'")
					if !ok || !strings.HasSuffix(name, "/accepted-install.json") {
						t.Fatal("peer gained allocator record write authority", selector)
					}
				}
			} else {
				actorWrites[permission] += branch
			}
		}
	}
	joined := strings.Join(entry.Request.Statements, "\n")
	for _, operation := range []string{"GetRetentionRule", "GetDynamicGroup", "LaunchInstance", "GetSecretBundle", "PutObject"} {
		if !strings.Contains(joined, "request.operation='"+operation+"'") {
			t.Fatal("v3 omitted required operation", operation)
		}
	}
	for _, slot := range []string{"controller-a", "controller-b", "controller-c"} {
		digest := sha256.Sum256([]byte(entry.Recipe.Cell + "\x00controller\x00" + slot))
		root := fmt.Sprintf("bootstrap/v1/%s/%x", entry.Startup.Producer.DeploymentID, digest)
		if entry.Startup.Producer.Home.Prefix != "" {
			root = entry.Startup.Producer.Home.Prefix + "/" + root
		}
		if !strings.Contains(peerWrites, "target.object.name='"+root+"/accepted-install.json'") {
			t.Fatal("peer lacks exact accepted-install create", slot)
		}
		if !strings.Contains(actorWrites["OBJECT_CREATE"], "target.object.name=/"+root+"/*/") {
			t.Fatal("original actor lacks immutable slot ledger create", slot)
		}
		for _, permission := range []string{"OBJECT_CREATE", "OBJECT_OVERWRITE"} {
			for _, selector := range []string{"target.object.name='" + root + "/head.json'", "target.object.name=/" + root + "/attempt-*/"} {
				if !strings.Contains(actorWrites[permission], selector) {
					t.Fatal("original actor lacks mutable slot allocation write", slot, permission, selector)
				}
			}
		}
	}
	if entry.Recipe.Cell == "GRU" {
		for _, region := range entry.Startup.Regions {
			for _, name := range region.LinkSecretNames {
				if name == "" || !strings.Contains(joined, "target.secret.name='"+name+"'") {
					t.Fatal("GRU Link publication omitted exact leaf", name)
				}
			}
			if !strings.Contains(joined, region.LinkObject) || !strings.Contains(joined, region.LinkEscrowSecretName) {
				t.Fatal("GRU lacks exact signed Link object or private escrow")
			}
			if region.Producer.Cell != "GRU" {
				for _, name := range region.SecretNames {
					if !slices.Contains(region.LinkSecretNames[:], name) && strings.Contains(joined, "target.secret.name='"+name+"'") {
						t.Fatal("GRU gained remote original33 publication beyond Link8", name)
					}
				}
			}
		}
	}
}

func TestOriginalFoundationMaterialIAMPeerGroupSDK(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	for _, fault := range []string{"lost group create response", "group reservation checkpoint", "group receipt checkpoint", "group completion checkpoint"} {
		t.Run(fault+" preserves retry", func(t *testing.T) {
			f := newOriginalMaterialIAMSDKFixture(t, fault)
			if err := f.run(t); err == nil || errors.Is(err, ErrOriginalFoundationMaterialIAMPending) || !f.faulted || len(f.posts) != 0 {
				t.Fatal("uncertain group admitted policy or startup", err)
			}
			var first *originalMaterialIAMDispatch
			if len(f.groupPosts) != 0 {
				first = new(f.groupPosts[0])
			}
			if err := f.run(t); !errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
				t.Fatal(err)
			}
			f.assertMaterialIAM(t)
			if first != nil && fault == "lost group create response" && (len(f.groupPosts) != 4 || f.groupPosts[1].token != first.token || !bytes.Equal(f.groupPosts[1].body, first.body) || !sameOriginalSourceValue(f.groupPosts[1].pending, first.pending)) {
				t.Fatal("unknown group outcome changed its acknowledged request")
			}
		})
	}
	for _, fault := range []string{"group readback conflict", "group ETag missing", "group duplicate id"} {
		t.Run(fault+" holds", func(t *testing.T) {
			f := newOriginalMaterialIAMSDKFixture(t, fault)
			if err := f.run(t); err == nil || errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
				t.Fatal("unproven peer group completed", err)
			}
			if fault != "group duplicate id" && len(f.posts) != 0 {
				t.Fatal("policy preceded exact group readback")
			}
		})
	}
	t.Run("current group drift blocks completed replay", func(t *testing.T) {
		f := newOriginalMaterialIAMSDKFixture(t, "")
		if err := f.run(t); !errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
			t.Fatal(err)
		}
		before, posts, groups := bytes.Clone(f.wire(t)), len(f.posts), len(f.groupPosts)
		f.fault = "group ETag changed"
		if err := f.run(t); err == nil || errors.Is(err, ErrOriginalFoundationMaterialIAMPending) || len(f.posts) != posts || len(f.groupPosts) != groups || !bytes.Equal(before, f.wire(t)) {
			t.Fatal("group drift changed history or admitted replay", err)
		}
	})
}

func TestOriginalFoundationMaterialIAMPeerGroupHistoryCannotResetSDK(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	f := newOriginalMaterialIAMSDKFixture(t, "")
	if err := f.run(t); !errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
		t.Fatal(err)
	}
	before := originalMaterialIAMSnapshot(t, f.cloud)
	for _, change := range []string{"remove group", "remove reservation", "remove receipt", "remove readback", "change request", "reuse provider id"} {
		t.Run(change, func(t *testing.T) {
			store := f.store(t)
			current, etag, err := store.Load(t.Context(), "GRU")
			if err != nil || etag == "" {
				t.Fatal("actual current journal unavailable", err)
			}
			entry := current.OriginalFoundationCompartments.Regions[0].MaterialPublicationIAM
			switch change {
			case "remove group":
				entry.PeerDynamicGroup = nil
			case "remove reservation":
				entry.PeerDynamicGroup.Pending = nil
			case "remove receipt":
				entry.PeerDynamicGroup.Provenance = nil
			case "remove readback":
				entry.PeerDynamicGroup.ETag, entry.PeerDynamicGroup.ReadbackSHA256, entry.PeerDynamicGroup.VerifiedAt = "", "", time.Time{}
			case "change request":
				entry.PeerDynamicGroup.Request.MatchingRule = new("ALL {instance.compartment.id='ocid1.compartment.oc1..foreign'}")
			case "reuse provider id":
				entry.PeerDynamicGroup.Provenance.ResourceID = current.OriginalFoundationCompartments.Regions[1].MaterialPublicationIAM.PeerDynamicGroup.Provenance.ResourceID
			}
			if _, err := store.CompareAndSwap(t.Context(), current, etag); err == nil {
				t.Fatal("actual protected CAS erased or replaced group history", change)
			}
			if !bytes.Equal(before, originalMaterialIAMSnapshot(t, f.cloud)) {
				t.Fatal("rejected group mutation changed durable cloud objects")
			}
		})
	}
}

// This finite test origin checks emitted branches, not OCI's complete IAM language.
func (f *originalMaterialIAMSDKFixture) assertRuntimeJoinSDK(t *testing.T, permitted bool) {
	t.Helper()
	entry := f.record(t).OriginalFoundationCompartments.Regions[0].MaterialPublicationIAM
	name := vaultsecret.Name(strings.ToLower(entry.Startup.Producer.Cell)+"-"+strings.ToLower(entry.Startup.Producer.ClusterID), "TS_ORCHESTRATOR_SWARM_JOIN")
	target := vaultsecret.Target{CompartmentID: entry.Target.CompartmentOCID, VaultID: entry.Target.VaultOCID, KeyID: entry.Target.KMSKeyOCID}
	type signer struct {
		principal string
		public    *rsa.PublicKey
	}
	signers := map[string]signer{}
	providers := map[string]common.ConfigurationProvider{}
	for _, principal := range []string{entry.ActorID, "peer", "foreign"} {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		wire := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		provider := common.NewRawConfigurationProvider(entry.Recipe.TenancyID, principal, entry.Recipe.OCIRegion, "runtime-join-fixture", string(wire), nil)
		keyID, err := provider.KeyID()
		if err != nil {
			t.Fatal(err)
		}
		signers[keyID] = signer{principal, &key.PublicKey}
		providers[principal] = provider
	}
	fieldsRE := regexp.MustCompile(`([a-zA-Z]+)="([^"]*)"`)
	verify := func(r *http.Request, body []byte) string {
		fields := map[string]string{}
		for _, match := range fieldsRE.FindAllStringSubmatch(r.Header.Get("Authorization"), -1) {
			fields[match[1]] = match[2]
		}
		signer, ok := signers[fields["keyId"]]
		if !ok || fields["algorithm"] != "rsa-sha256" {
			return ""
		}
		seen := map[string]bool{}
		var lines []string
		for header := range strings.FieldsSeq(fields["headers"]) {
			if seen[header] {
				return ""
			}
			seen[header] = true
			value := r.Header.Get(header)
			switch header {
			case "(request-target)":
				value = strings.ToLower(r.Method) + " " + r.URL.RequestURI()
			case "host":
				value = r.Host
			case "content-length":
				value = strconv.FormatInt(r.ContentLength, 10)
			}
			lines = append(lines, header+": "+value)
		}
		if !seen["(request-target)"] || !seen["host"] || !seen["date"] && !seen["x-date"] {
			return ""
		}
		if r.Method == http.MethodPost {
			digest := sha256.Sum256(body)
			if !seen["x-content-sha256"] || !seen["content-length"] || r.ContentLength != int64(len(body)) || r.Header.Get("X-Content-Sha256") != base64.StdEncoding.EncodeToString(digest[:]) {
				return ""
			}
		}
		signature, err := base64.StdEncoding.DecodeString(fields["signature"])
		digest := sha256.Sum256([]byte(strings.Join(lines, "\n")))
		if err != nil || rsa.VerifyPKCS1v15(signer.public, crypto.SHA256, digest[:], signature) != nil {
			return ""
		}
		return signer.principal
	}
	allows := func(principal, resource, operation, permission, compartment, vault, key, secret string) bool {
		for _, statement := range entry.Request.Statements {
			prefix := "Allow any-user to "
			if principal == "peer" {
				prefix = "Allow dynamic-group " + deref(entry.PeerDynamicGroup.Request.Name) + " "
			} else if principal != entry.ActorID {
				continue
			}
			if !strings.HasPrefix(statement, prefix) || !strings.Contains(statement, " "+resource+" in compartment id "+compartment+" where ") {
				continue
			}
			if principal == entry.ActorID && !strings.Contains(statement, "request.principal.id='"+entry.ActorID+"'") {
				continue
			}
			for _, branch := range strings.Split(statement, "all {request.operation='")[1:] {
				if !strings.HasPrefix(branch, operation+"', request.permission='"+permission+"'") {
					continue
				}
				matches := true
				for selector, value := range map[string]string{"target.vault.id": vault, "target.key.id": key, "target.secret.name": secret} {
					if strings.Contains(branch, selector+"=") && !strings.Contains(branch, selector+"='"+value+"'") {
						matches = false
					}
				}
				if matches {
					return true
				}
			}
		}
		return false
	}
	created, published, createAttempts, reads := false, false, 0, 0
	content := base64.StdEncoding.EncodeToString([]byte("fixture-join-value"))
	f.materialMu.Lock()
	f.joinHTTP = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		principal := verify(r, body)
		deny := func() { originalCompartmentFailure(w, http.StatusForbidden, "NotAuthorizedOrNotFound") }
		if err != nil || principal == "" || !strings.Contains(r.Host, "."+entry.Recipe.OCIRegion+".") {
			deny()
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/20180608/secrets" {
			if !allows(principal, "secrets", "ListSecrets", "SECRET_INSPECT", r.URL.Query().Get("compartmentId"), "", "", "") {
				deny()
				return
			}
			json.MarshalWrite(w, []any{})
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/20180608/secrets" {
			createAttempts++
			var request struct {
				CompartmentID string `json:"compartmentId"`
				VaultID       string `json:"vaultId"`
				KeyID         string `json:"keyId"`
				Name          string `json:"secretName"`
				Content       struct {
					Value string `json:"content"`
				} `json:"secretContent"`
			}
			if json.Unmarshal(body, &request) != nil {
				deny()
				return
			}
			for _, required := range [][2]string{{"secrets", "SECRET_CREATE"}, {"vaults", "VAULT_CREATE_SECRET"}, {"keys", "KEY_ENCRYPT"}, {"keys", "KEY_DECRYPT"}} {
				if !allows(principal, required[0], "CreateSecret", required[1], request.CompartmentID, request.VaultID, request.KeyID, request.Name) {
					deny()
					return
				}
			}
			created, published, content = true, true, request.Content.Value
			json.MarshalWrite(w, map[string]any{"id": "ocid1.vaultsecret.oc1.sa-saopaulo-1.runtimejoin", "secretName": request.Name, "lifecycleState": "ACTIVE"})
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/20190301/secretbundles/actions/getByName" {
			reads++
			if !created || !allows(principal, "secret-bundles", "GetSecretBundleByName", "SECRET_BUNDLE_READ", target.CompartmentID, r.URL.Query().Get("vaultId"), "", r.URL.Query().Get("secretName")) {
				deny()
				return
			}
			json.MarshalWrite(w, map[string]any{"secretId": "ocid1.vaultsecret.oc1.sa-saopaulo-1.runtimejoin", "versionNumber": 1, "secretBundleContent": map[string]any{"contentType": "BASE64", "content": content}})
			return
		}
		t.Errorf("unexpected runtime join SDK route %s %s", r.Method, r.URL.Path)
		deny()
	})
	f.materialMu.Unlock()
	defer func() { f.materialMu.Lock(); f.joinHTTP = nil; f.materialMu.Unlock() }()
	clients := func(principal, region string) (ocivault.VaultsClient, ocisecrets.SecretsClient) {
		management, err := ocivault.NewVaultsClientWithConfigurationProvider(providers[principal])
		if err != nil {
			t.Fatal(err)
		}
		bundles, err := ocisecrets.NewSecretsClientWithConfigurationProvider(providers[principal])
		if err != nil {
			t.Fatal(err)
		}
		management.Host = "https://vaults." + region + ".oci.oraclecloud.com"
		bundles.Host = "https://secrets.vaults." + region + ".oci.oraclecloud.com"
		return management, bundles
	}
	for _, change := range []string{"none", "principal", "name", "vault", "key", "compartment", "region", "peer"} {
		principal, region, selected, selectedName := entry.ActorID, entry.Recipe.OCIRegion, target, name
		switch change {
		case "principal":
			principal = "foreign"
		case "peer":
			principal = "peer"
		case "name":
			selectedName += "-foreign"
		case "vault":
			selected.VaultID += "foreign"
		case "key":
			selected.KeyID += "foreign"
		case "compartment":
			selected.CompartmentID += "foreign"
		case "region":
			region = "us-ashburn-1"
		}
		management, _ := clients(principal, region)
		created = false
		stored, err := vaultsecret.Ensure(t.Context(), management, selected, selectedName, "runtime join fixture", func(context.Context) (string, error) { return "fixture-join-value", nil })
		want := permitted && change == "none"
		if (err == nil) != want || created != want || stored.Created != want {
			t.Fatalf("runtime join create %s: accepted=%v want=%v", change, err == nil, want)
		}
	}
	// Historical read refusal also holds when the exact secret already exists.
	if permitted && !published {
		t.Fatal("actual actor never published join material")
	}
	created = true
	for _, change := range []string{"actor", "peer", "principal", "name", "vault", "region"} {
		principal, region, selectedVault, selectedName := entry.ActorID, entry.Recipe.OCIRegion, target.VaultID, name
		switch change {
		case "peer":
			principal = "peer"
		case "principal":
			principal = "foreign"
		case "name":
			selectedName += "-foreign"
		case "vault":
			selectedVault += "foreign"
		case "region":
			region = "us-ashburn-1"
		}
		_, bundles := clients(principal, region)
		value, err := vaultsecret.Read(t.Context(), bundles, selectedVault, selectedName)
		want := permitted && (change == "actor" || change == "peer")
		if (err == nil) != want || want && value != "fixture-join-value" {
			t.Fatalf("runtime join by-name read %s: accepted=%v want=%v", change, err == nil, want)
		}
	}
	if createAttempts == 0 || reads == 0 {
		t.Fatal("runtime join assertions missed actual signed SDK routes")
	}
}

func TestOriginalFoundationMaterialIAMSDK(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	t.Run("automatic completion and unchanged restart", func(t *testing.T) {
		f := newOriginalMaterialIAMSDKFixture(t, "")
		if err := f.run(t); !errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
			t.Fatal(err)
		}
		f.assertMaterialIAM(t)
		f.assertRuntimeJoinSDK(t, true)
		before, posts, puts := bytes.Clone(f.wire(t)), len(f.posts), f.journalPuts
		public := f.puts
		if posts != 3 {
			t.Fatal("material IAM did not create exactly one finite policy per original actor")
		}
		for _, regional := range f.record(t).OriginalFoundationCompartments.Regions {
			entry := regional.MaterialPublicationIAM
			if entry.Recipe.Purpose != originalMaterialIAMPurposeV4 || entry.Recipe.RuntimeJoinSecretName == "" || entry.Recipe.PolicyRead == nil || entry.PeerDynamicGroup == nil || entry.PeerDynamicGroup.VerifiedAt.IsZero() || len(entry.Request.Statements) > 50 {
				t.Fatal("fresh preparation lacks prospective v4, actual peer group or a deployable finite policy")
			}
		}
		if err := f.run(t); !errors.Is(err, ErrOriginalFoundationMaterialIAMPending) || len(f.posts) != posts || f.journalPuts != puts || f.puts != public || !bytes.Equal(before, f.wire(t)) {
			t.Fatal("completed material IAM replay changed history or repeated effects", err)
		}
	})
	t.Run("unknown create outcome keeps body and retry token", func(t *testing.T) {
		f := newOriginalMaterialIAMSDKFixture(t, "lost create response")
		if err := f.run(t); err == nil || errors.Is(err, ErrOriginalFoundationMaterialIAMPending) || !f.faulted || len(f.posts) != 1 {
			t.Fatal("unknown material create outcome became completion", err)
		}
		pending := f.posts[0]
		if err := f.run(t); !errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
			t.Fatal(err)
		}
		f.assertMaterialIAM(t)
		if len(f.posts) != 4 || f.posts[1].token != pending.token || !bytes.Equal(f.posts[1].body, pending.body) || !sameOriginalSourceValue(f.posts[1].pending, pending.pending) {
			t.Fatal("unknown material create outcome changed immutable retry identity")
		}
	})
	for _, fault := range []string{"scope checkpoint", "reservation checkpoint", "receipt checkpoint", "completion checkpoint", "lost reservation checkpoint", "lost receipt checkpoint", "lost completion checkpoint"} {
		t.Run(fault+" resumes", func(t *testing.T) {
			f := newOriginalMaterialIAMSDKFixture(t, fault)
			if err := f.run(t); err == nil || errors.Is(err, ErrOriginalFoundationMaterialIAMPending) || !f.faulted {
				t.Fatal("failed material checkpoint became completed authority", err)
			}
			if strings.Contains(fault, "scope") || strings.Contains(fault, "reservation") {
				if len(f.posts) != 0 {
					t.Fatal("material effect preceded acknowledged protected reservation")
				}
			}
			var pending *PendingFoundationCreate
			if entry := f.record(t).OriginalFoundationCompartments.Regions[0].MaterialPublicationIAM; entry != nil && entry.Pending != nil {
				value := *entry.Pending
				pending = &value
			}
			if err := f.run(t); !errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
				t.Fatal(err)
			}
			f.assertMaterialIAM(t)
			if pending != nil && !sameOriginalSourceValue(pending, f.record(t).OriginalFoundationCompartments.Regions[0].MaterialPublicationIAM.Pending) {
				t.Fatal("checkpoint recovery changed reserved material request")
			}
		})
	}
	for _, fault := range []string{"readback missing", "readback unavailable", "readback conflict", "readback compartment", "readback pending deletion", "readback ETag missing"} {
		t.Run(fault+" cannot complete", func(t *testing.T) {
			f := newOriginalMaterialIAMSDKFixture(t, fault)
			if err := f.run(t); err == nil || errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
				t.Fatal("missing or changed material policy became completion", err)
			}
			entry := f.record(t).OriginalFoundationCompartments.Regions[0].MaterialPublicationIAM
			if entry == nil || entry.Provenance == nil || !entry.VerifiedAt.IsZero() || entry.ReadbackSHA256 != "" || entry.PolicyETag != "" || len(f.posts) != 1 || f.cloud.hasAnchor() {
				t.Fatal("uncertain policy readback fabricated completion or ordinary admission")
			}
		})
	}
	t.Run("permanent create refusal retains HOLD", func(t *testing.T) {
		f := newOriginalMaterialIAMSDKFixture(t, "create refused")
		if err := f.run(t); err == nil || errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
			t.Fatal("refused material create became completion", err)
		}
		entry := f.record(t).OriginalFoundationCompartments.Regions[0].MaterialPublicationIAM
		if entry == nil || entry.Pending == nil || entry.Provenance != nil || entry.HoldReason != "create-refused" || len(f.posts) != 1 {
			t.Fatal("permanent refusal lost reserved history")
		}
		before := bytes.Clone(f.wire(t))
		if err := f.run(t); err == nil || len(f.posts) != 1 || !bytes.Equal(before, f.wire(t)) {
			t.Fatal("permanent refusal recreated or reset material policy")
		}
	})
	t.Run("retained ETag does not replace current provider policy", func(t *testing.T) {
		f := newOriginalMaterialIAMSDKFixture(t, "")
		if err := f.run(t); !errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
			t.Fatal(err)
		}
		before, posts, puts := bytes.Clone(f.wire(t)), len(f.posts), f.journalPuts
		f.materialMu.Lock()
		f.fault = "readback ETag changed"
		f.materialMu.Unlock()
		if err := f.run(t); err == nil || errors.Is(err, ErrOriginalFoundationMaterialIAMPending) || !bytes.Equal(before, f.wire(t)) || len(f.posts) != posts || f.journalPuts != puts {
			t.Fatal("retained receipt replaced current exact policy ETag or recreated policy", err)
		}
	})
	t.Run("historical v3 retains exact policy without join authority", func(t *testing.T) {
		reads := newOriginalActorReadsSDKFixture(t, "", 0)
		recipes := *reads.prepared.Grant.OriginalMaterialPublicationIAM
		for index := range recipes {
			recipes[index].Purpose = originalMaterialIAMPurposeV3
			recipes[index].RuntimeJoinSecretName = ""
		}
		reads.prepared.Grant.OriginalMaterialPublicationIAM = &recipes
		f := originalMaterialIAMSDKFixtureFor(t, reads, "")
		if err := f.run(t); !errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
			t.Fatal(err)
		}
		f.assertMaterialIAM(t)
		f.assertRuntimeJoinSDK(t, false)
		for _, regional := range f.record(t).OriginalFoundationCompartments.Regions {
			entry := regional.MaterialPublicationIAM
			if entry.Recipe.Purpose != originalMaterialIAMPurposeV3 || entry.Recipe.RuntimeJoinSecretName != "" || strings.Contains(strings.Join(entry.Request.Statements, "\n"), "ts-orchestrator-swarm-join") {
				t.Fatal("historical v3 acquired join authority")
			}
		}
		before, posts, puts := bytes.Clone(f.wire(t)), len(f.posts), f.journalPuts
		if err := f.run(t); !errors.Is(err, ErrOriginalFoundationMaterialIAMPending) || len(f.posts) != posts || f.journalPuts != puts || !bytes.Equal(before, f.wire(t)) {
			t.Fatal("historical v3 restart rewrote policy or journal", err)
		}
		beforeCloud := originalMaterialIAMSnapshot(t, f.cloud)
		store := f.store(t)
		current, etag, err := store.Load(t.Context(), "GRU")
		if err != nil {
			t.Fatal(err)
		}
		entry := current.OriginalFoundationCompartments.Regions[0].MaterialPublicationIAM
		entry.Recipe.Purpose = originalMaterialIAMPurposeV4
		entry.Recipe.RuntimeJoinSecretName = vaultsecret.Name(strings.ToLower(entry.Startup.Producer.Cell)+"-"+strings.ToLower(entry.Startup.Producer.ClusterID), "TS_ORCHESTRATOR_SWARM_JOIN")
		if _, err := store.CompareAndSwap(t.Context(), current, etag); err == nil || !bytes.Equal(beforeCloud, originalMaterialIAMSnapshot(t, f.cloud)) {
			t.Fatal("protected CAS upgraded retained v3 history", err)
		}
	})
	t.Run("signed historical absence retains old HOLD", func(t *testing.T) {
		f := newOriginalPublicationSDKFixture(t, "")
		if f.prepared.Grant.OriginalMaterialPublicationIAM != nil {
			t.Fatal("historical fixture has new prospective material permission")
		}
		if err := f.run(t); !errors.Is(err, ErrOriginalFoundationAdmissionReadsPending) || errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
			t.Fatal("historical signed absence changed existing HOLD", err)
		}
		f.assertPublished(t)
		for _, regional := range f.record(t).OriginalFoundationCompartments.Regions {
			if regional.MaterialPublicationIAM != nil {
				t.Fatal("historical absence acquired material IAM effects")
			}
		}
	})
}

// This historical wire schema deliberately has no policyRead field.
type originalMaterialIAMV1Wire struct {
	Purpose                      string                                 `json:"purpose"`
	Cell                         string                                 `json:"cell"`
	OCIRegion                    string                                 `json:"ociRegion"`
	TenancyID                    string                                 `json:"tenancyId"`
	InstallationID               string                                 `json:"installationId"`
	ProducerIntentSHA256         string                                 `json:"producerIntentSha256"`
	PlanSHA256                   string                                 `json:"planSha256"`
	AdmissionAuthorizationSHA256 string                                 `json:"admissionAuthorizationSha256"`
	ActorOperationID             string                                 `json:"actorOperationId"`
	ActorRecipeSHA256            string                                 `json:"actorRecipeSha256"`
	ControlCompartment           string                                 `json:"controlCompartment"`
	Vault                        string                                 `json:"vault"`
	Key                          string                                 `json:"key"`
	SecretNames                  []string                               `json:"secretNames"`
	Operations                   [7]OriginalActorAdmissionReadOperation `json:"operations"`
}

type originalMaterialIAMV2Wire struct {
	originalMaterialIAMV1Wire
	PolicyRead *OriginalActorAdmissionReadOperation `json:"policyRead,omitempty"`
}

func TestOriginalFoundationMaterialIAMV1Compatibility(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	t.Setenv(common.UsingExpectHeaderEnvVar, "false")
	reads := newOriginalActorReadsSDKFixture(t, "", 0)
	if reads.prepared.Grant.OriginalMaterialPublicationIAM == nil {
		t.Fatal("prospective preparation omitted material IAM")
	}
	recipes := *reads.prepared.Grant.OriginalMaterialPublicationIAM
	for index := range recipes {
		if recipes[index].Purpose != originalMaterialIAMPurposeV4 || recipes[index].PolicyRead == nil {
			t.Fatal("fresh preparation did not produce v4")
		}
		recipes[index].Purpose, recipes[index].PolicyRead = originalMaterialIAMPurpose, nil
		recipes[index].RuntimeJoinSecretName = ""
		recipes[index].LinkSecretNames, recipes[index].LinkObject, recipes[index].LinkEscrowSecretName = [8]string{}, "", ""
	}
	reads.prepared.Grant.OriginalMaterialPublicationIAM = &recipes
	if err := validateOriginalMaterialIAMIntents(reads.prepared.Grant, reads.approval.HomeStorageDomain); err != nil {
		t.Fatal("historical v1 signed contract rejected", err)
	}
	wire, err := json.Marshal(recipes, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	var legacy [3]originalMaterialIAMV1Wire
	if err := json.Unmarshal(wire, &legacy); err != nil {
		t.Fatal(err)
	}
	legacyWire, err := json.Marshal(legacy, json.Deterministic(true))
	if err != nil || !bytes.Equal(wire, legacyWire) || digestSource(wire) != digestSource(legacyWire) || bytes.Contains(wire, []byte("policyRead")) {
		t.Fatal("nil policyRead changed historical v1 wire or digest", err)
	}
	reconstructed, err := originalMaterialIAMIntents(reads.prepared.Grant, reads.approval.HomeStorageDomain)
	if err != nil || !sameOriginalSourceValue(reconstructed, recipes) {
		t.Fatal("historical signed purpose was upgraded during reconstruction", err)
	}
	f := originalMaterialIAMSDKFixtureFor(t, reads, "")
	if err := f.run(t); !errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
		t.Fatal(err)
	}
	f.assertMaterialIAM(t)
	for _, regional := range f.record(t).OriginalFoundationCompartments.Regions {
		entry := regional.MaterialPublicationIAM
		if entry.Recipe.Purpose != originalMaterialIAMPurpose || entry.Recipe.PolicyRead != nil || len(entry.Request.Statements) != 7 {
			t.Fatal("historical coordinator upgraded v1 recipe or policy")
		}
	}
	before, posts, puts, public := bytes.Clone(f.wire(t)), len(f.posts), f.journalPuts, f.puts
	if err := f.run(t); !errors.Is(err, ErrOriginalFoundationMaterialIAMPending) || !bytes.Equal(before, f.wire(t)) || len(f.posts) != posts || f.journalPuts != puts || f.puts != public {
		t.Fatal("historical v1 restart changed signed journal or repeated effects", err)
	}
	beforeCloud := originalMaterialIAMSnapshot(t, f.cloud)
	store := f.store(t)
	current, etag, err := store.Load(t.Context(), "GRU")
	if err != nil || etag == "" {
		t.Fatal("missing actual current v1 store ETag", err)
	}
	entry := current.OriginalFoundationCompartments.Regions[0].MaterialPublicationIAM
	entry.Recipe.Purpose = originalMaterialIAMPurposeV2
	entry.Recipe.PolicyRead = new(OriginalActorAdmissionReadOperation{"GetPolicy", "policies", "POLICY_READ", "regional-control-policy-read"})
	if _, err := store.CompareAndSwap(t.Context(), current, etag); err == nil {
		t.Fatal("actual protected CAS upgraded retained v1 recipe")
	}
	if !bytes.Equal(beforeCloud, originalMaterialIAMSnapshot(t, f.cloud)) || len(f.posts) != posts || f.journalPuts != puts || f.puts != public {
		t.Fatal("rejected v1 upgrade changed durable objects or effects")
	}
}

func TestOriginalFoundationMaterialIAMV2Compatibility(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	t.Setenv(common.UsingExpectHeaderEnvVar, "false")
	reads := newOriginalActorReadsSDKFixture(t, "", 0)
	recipes := *reads.prepared.Grant.OriginalMaterialPublicationIAM
	for index := range recipes {
		recipes[index].Purpose = originalMaterialIAMPurposeV2
		recipes[index].RuntimeJoinSecretName = ""
		recipes[index].LinkSecretNames, recipes[index].LinkObject, recipes[index].LinkEscrowSecretName = [8]string{}, "", ""
		reads.prepared.Grant.Regions[index].BootstrapMaterial.OriginalStartupAdmission = nil
	}
	reads.prepared.Grant.OriginalMaterialPublicationIAM = &recipes
	f := originalMaterialIAMSDKFixtureFor(t, reads, "")
	wire, err := json.Marshal(recipes, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	var legacy [3]originalMaterialIAMV2Wire
	if err := json.Unmarshal(wire, &legacy); err != nil {
		t.Fatal(err)
	}
	legacyWire, err := json.Marshal(legacy, json.Deterministic(true))
	if err != nil || !bytes.Equal(wire, legacyWire) || digestSource(wire) != digestSource(legacyWire) {
		t.Fatal("optional v3 fields changed historical v2 wire or digest", err)
	}
	if err := f.run(t); !errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
		t.Fatal(err)
	}
	f.assertMaterialIAM(t)
	before, posts, puts := bytes.Clone(f.wire(t)), len(f.posts), f.journalPuts
	for _, region := range f.record(t).OriginalFoundationCompartments.Regions {
		entry := region.MaterialPublicationIAM
		if entry.Recipe.Purpose != originalMaterialIAMPurposeV2 || entry.PeerDynamicGroup != nil || entry.Startup != nil || len(entry.Request.Statements) != 8 || deref(entry.Request.CompartmentId) != entry.Target.CompartmentOCID {
			t.Fatal("historical v2 was reinterpreted as startup authority")
		}
	}
	if len(f.groupPosts) != 0 {
		t.Fatal("historical v2 created a prospective group")
	}
	if err := f.run(t); !errors.Is(err, ErrOriginalFoundationMaterialIAMPending) || len(f.posts) != posts || f.journalPuts != puts || !bytes.Equal(before, f.wire(t)) {
		t.Fatal("v2 replay rewrote completed history", err)
	}
}

func TestOriginalFoundationMaterialIAMSignedContract(t *testing.T) {
	// Preserve the fixture's literal loopback transport through SDK client construction.
	t.Setenv(common.UsingExpectHeaderEnvVar, "false")
	for _, change := range []string{"purpose", "join name", "missing join name", "historical join name", "name", "owner name", "vault", "key", "control", "actor recipe", "permission", "key encrypt operation", "key decrypt operation", "LIST scope", "missing policy read", "policy list", "policy resource", "policy permission", "policy scope", "v1 policy read", "mixed version"} {
		t.Run(change, func(t *testing.T) {
			f := newOriginalActorReadsSDKFixture(t, "", 0)
			prepared := f.prepared
			if prepared.Grant.OriginalMaterialPublicationIAM == nil {
				t.Fatal("prospective preparation omitted material IAM")
			}
			recipes := *prepared.Grant.OriginalMaterialPublicationIAM
			for index := range recipes {
				recipes[index].SecretNames = slices.Clone(recipes[index].SecretNames)
				if recipes[index].PolicyRead != nil {
					recipes[index].PolicyRead = new(*recipes[index].PolicyRead)
				}
			}
			prepared.Grant.OriginalMaterialPublicationIAM = &recipes
			switch change {
			case "purpose":
				recipes[0].Purpose = "publish-arbitrary-material"
			case "join name":
				recipes[0].RuntimeJoinSecretName += "-foreign"
			case "missing join name":
				recipes[0].RuntimeJoinSecretName = ""
			case "historical join name":
				for index := range recipes {
					recipes[index].Purpose = originalMaterialIAMPurposeV3
				}
			case "name":
				recipes[0].SecretNames[0] += "-foreign"
			case "owner name":
				recipes[0].SecretNames = append(recipes[0].SecretNames, "issuer-operator-seed")
			case "vault":
				recipes[1].Vault = recipes[0].Vault
			case "key":
				recipes[1].Key = recipes[0].Key
			case "control":
				recipes[1].ControlCompartment = recipes[0].ControlCompartment
			case "actor recipe":
				recipes[0].ActorRecipeSHA256 = strings.Repeat("0", 64)
			case "permission":
				recipes[0].Operations[1].Permission = "SECRET_UPDATE"
			case "key encrypt operation":
				recipes[0].Operations[5].Operation = "Encrypt"
			case "key decrypt operation":
				recipes[0].Operations[6].Operation = "Decrypt"
			case "LIST scope":
				recipes[0].Operations[0].Scope = "material-names-vault"
			case "missing policy read":
				recipes[0].PolicyRead = nil
			case "policy list":
				recipes[0].PolicyRead.Operation = "ListPolicies"
			case "policy resource":
				recipes[0].PolicyRead.ResourceType = "all-resources"
			case "policy permission":
				recipes[0].PolicyRead.Permission = "POLICY_UPDATE"
			case "policy scope":
				recipes[0].PolicyRead.Scope = "material-names-vault"
			case "v1 policy read":
				for index := range recipes {
					recipes[index].Purpose = originalMaterialIAMPurpose
				}
			case "mixed version":
				recipes[1].Purpose, recipes[1].PolicyRead = originalMaterialIAMPurpose, nil
			}
			if validateOriginalMaterialIAMIntents(prepared.Grant, f.approval.HomeStorageDomain) == nil {
				t.Fatal("changed finite recipe passed direct validation")
			}
			f.bundle = signProvisionFoundation(t, prepared, f.bundle.RootChainWire, f.root, f.now)
			f.cloud.bundle = f.bundle.clone()
			var err error
			f.publicBundle, err = json.Marshal(f.bundle, json.Deterministic(true))
			if err != nil {
				t.Fatal(err)
			}
			before := originalMaterialIAMSnapshot(t, f.cloud)
			if f.cloud.creates != 0 || f.cloud.materialPosts != 0 || f.cloud.launchPosts != 0 {
				t.Fatal("signed recipe mutation began after adoption")
			}
			if err := provisionOriginalFoundationCompartments(t.Context(), f.factoryFor(), f.roots, f.bundle); err == nil {
				t.Fatal("actual coordinator accepted altered signed material recipe")
			}
			if !bytes.Equal(before, originalMaterialIAMSnapshot(t, f.cloud)) || f.cloud.creates != 0 || f.cloud.materialPosts != 0 || f.cloud.launchPosts != 0 || len(f.dispatches()) != 0 || f.cloud.hasAnchor() {
				t.Fatal("altered signed recipe changed durable objects or dispatched effects")
			}
		})
	}
}

func TestOriginalFoundationMaterialIAMRetainedContract(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	f := newOriginalMaterialIAMSDKFixture(t, "")
	if err := f.run(t); !errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
		t.Fatal(err)
	}
	f.assertMaterialIAM(t)
	store := f.store(t)
	for _, change := range []string{"remove", "actor", "vault", "join name", "missing join name", "historical join name", "name", "statement", "token", "receipt", "ETag", "completion", "policy read", "purpose downgrade"} {
		t.Run(change, func(t *testing.T) {
			current, etag, err := store.Load(t.Context(), "GRU")
			if err != nil || etag == "" {
				t.Fatal("missing actual current store ETag", err)
			}
			previous := f.record(t)
			entry := current.OriginalFoundationCompartments.Regions[0].MaterialPublicationIAM
			switch change {
			case "remove":
				current.OriginalFoundationCompartments.Regions[0].MaterialPublicationIAM = nil
			case "actor":
				entry.ActorID = current.OriginalFoundationCompartments.Regions[1].Actor.Provenance.ResourceID
			case "vault":
				entry.Target.VaultOCID = current.OriginalFoundationCompartments.Regions[1].MaterialPublicationIAM.Target.VaultOCID
			case "join name":
				entry.Recipe.RuntimeJoinSecretName += "-foreign"
			case "missing join name":
				entry.Recipe.RuntimeJoinSecretName = ""
			case "historical join name":
				entry.Recipe.Purpose = originalMaterialIAMPurposeV3
			case "name":
				entry.Recipe.SecretNames[0] += "-different"
			case "statement":
				entry.Request.Statements = append(entry.Request.Statements, "Allow any-user to manage all-resources in tenancy")
			case "token":
				entry.Pending.Request.RetryToken = "different"
			case "receipt":
				entry.Provenance.ResourceID = current.OriginalFoundationCompartments.Regions[1].MaterialPublicationIAM.Provenance.ResourceID
			case "ETag":
				entry.PolicyETag = "different"
			case "completion":
				entry.VerifiedAt = entry.VerifiedAt.Add(time.Nanosecond)
			case "policy read":
				entry.Recipe.PolicyRead.Operation = "ListPolicies"
			case "purpose downgrade":
				entry.Recipe.Purpose, entry.Recipe.PolicyRead = originalMaterialIAMPurpose, nil
			}
			if current.validate() == nil && current.retainOriginalFoundationMaterialIAM(previous) == nil {
				t.Fatal("changed retained material policy passed direct contract")
			}
			before, posts, puts, public := originalMaterialIAMSnapshot(t, f.cloud), len(f.posts), f.journalPuts, f.puts
			if _, err := store.CompareAndSwap(t.Context(), current, etag); err == nil {
				t.Fatal("actual protected CAS changed retained material identity")
			}
			if !bytes.Equal(before, originalMaterialIAMSnapshot(t, f.cloud)) || len(f.posts) != posts || f.journalPuts != puts || f.puts != public {
				t.Fatal("rejected retained mutation changed durable objects or effects")
			}
		})
	}
}

func TestOriginalFoundationMaterialIAMEffectPredecessors(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	for _, fault := range []string{"reservation checkpoint", "receipt checkpoint"} {
		t.Run(fault, func(t *testing.T) {
			f := newOriginalMaterialIAMSDKFixture(t, fault)
			if err := f.run(t); err == nil || errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
				t.Fatal("fixture did not stop at actual effect predecessor")
			}
			store := f.store(t)
			current, etag, err := store.Load(t.Context(), "GRU")
			if err != nil {
				t.Fatal(err)
			}
			entry := current.OriginalFoundationCompartments.Regions[0].MaterialPublicationIAM
			if entry == nil || entry.Provenance != nil {
				t.Fatal("unexpected receipt predecessor")
			}
			if fault == "receipt checkpoint" && (entry.Pending == nil || len(f.posts) != 1 || f.rows["ocid1.policy.oc1..originalmaterial1"] == nil) {
				t.Fatal("receipt predecessor lacks genuine provider create")
			}
			if entry.Pending == nil {
				body, err := foundationWriterPolicyBody(entry.Request)
				if err != nil {
					t.Fatal(err)
				}
				regional := current.OriginalFoundationCompartments.Regions[0]
				entry.Pending = &PendingFoundationCreate{OperationID: regional.OperationID, IntentDigest: regional.IntentSHA256, FirstAttemptAt: time.Now().UTC(), Request: originalMaterialIAMCreateIdentity(regional, digestSource(body))}
			}
			// These rejected DATA claims cannot create authority or replace a real predecessor.
			entry.Provenance = &FoundationResourceProvenance{Create: *entry.Pending, ResourceID: "ocid1.policy.oc1..originalmaterial1", Generation: entry.Generation, GrantSHA256: entry.GrantSHA256}
			if fault == "receipt checkpoint" {
				wire, err := json.Marshal(f.rows[entry.Provenance.ResourceID], json.Deterministic(true))
				if err != nil {
					t.Fatal(err)
				}
				entry.PolicyETag = digestSource(wire)
				entry.ReadbackSHA256, err = originalMaterialIAMReadback(*entry)
				if err != nil {
					t.Fatal(err)
				}
				entry.VerifiedAt = time.Now().UTC()
			}
			current.UpdatedAt = time.Now().UTC()
			if err := current.validate(); err != nil {
				t.Fatal("candidate must be structurally valid before predecessor refusal", err)
			}
			before, posts, puts := originalMaterialIAMSnapshot(t, f.cloud), len(f.posts), f.journalPuts
			if _, err := store.CompareAndSwap(t.Context(), current, etag); !errors.Is(err, ErrOriginalSourceProducerHold) || !bytes.Equal(before, originalMaterialIAMSnapshot(t, f.cloud)) || len(f.posts) != posts || f.journalPuts != puts {
				t.Fatal("actual protected CAS skipped acknowledged material effect predecessor")
			}
		})
	}
}

func TestOriginalFoundationMaterialIAMRequiresOwningLease(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	if err := provisionOriginalFoundationMaterialIAM(t.Context(), nil); err == nil {
		t.Fatal("nil original operator acquired material IAM")
	}
	if _, _, _, _, err := originalMaterialIAMPrerequisites(nil, nil); err == nil {
		t.Fatal("nil context acquired material IAM")
	}
	f := newOriginalMaterialIAMSDKFixture(t, "")
	if err := f.run(t); !errors.Is(err, ErrOriginalFoundationMaterialIAMPending) {
		t.Fatal(err)
	}
	authority, _, err := newOperatorHomeIAMAuthority(t.Context(), f.factoryFor(), f.roots, f.bundle)
	if err != nil {
		t.Fatal(err)
	}
	before, posts := originalMaterialIAMSnapshot(t, f.cloud), len(f.posts)
	if err := provisionOriginalFoundationMaterialIAM(t.Context(), authority); err == nil || !bytes.Equal(before, originalMaterialIAMSnapshot(t, f.cloud)) || len(f.posts) != posts {
		t.Fatal("missing genuine HomeWrite lease acquired material IAM")
	}
}

func TestOriginalMaterialPublicationNamesMatchActualProducer(t *testing.T) {
	// The existing vendor setting keeps factory transports within literal loopback TLS.
	t.Setenv(common.UsingExpectHeaderEnvVar, "false")
	f := newOriginalActorReadsSDKFixture(t, "", 0)
	material := f.prepared.Grant.Regions[0].BootstrapMaterial
	directory := filepath.Join(t.TempDir(), "candidate")
	record, err := bootstrapmaterial.GenerateAdmissionCandidate(directory, material.Config, *material.AdmissionAttestor, f.now)
	if err != nil {
		t.Fatal(err)
	}
	names, err := bootstrapmaterial.OriginalPublicationSecretNames(material.Config)
	if err != nil || len(names) != 33 {
		t.Fatal(err)
	}
	management, err := ocivault.NewVaultsClientWithConfigurationProvider(f.provider)
	if err != nil {
		t.Fatal(err)
	}
	bundles, err := ocisecrets.NewSecretsClientWithConfigurationProvider(f.provider)
	if err != nil {
		t.Fatal(err)
	}
	stop := errors.New("stop after actual publication journal, before SDK effects")
	var selected []string
	var files []string
	_, err = bootstrapmaterial.ProvisionDurable(t.Context(), directory, material.SourceVaultTarget, management, bundles, f.now, func(wire []byte) error {
		var journal struct {
			Entries []struct {
				Name     string `json:"name"`
				FileName string `json:"fileName"`
			} `json:"entries"`
		}
		if err := json.Unmarshal(wire, &journal); err != nil {
			t.Fatal(err)
		}
		for _, entry := range journal.Entries {
			selected = append(selected, entry.Name)
			files = append(files, entry.FileName)
		}
		return stop
	})
	if !errors.Is(err, stop) {
		t.Fatal("actual producer did not expose initial journal before effect", err)
	}
	slices.Sort(selected)
	if !slices.Equal(names, selected) {
		t.Fatal("IAM helper roster differs from actual publication naming")
	}
	for _, file := range record.Files {
		if slices.Contains(files, file.Name) != (file.Purpose != "owner-only") {
			t.Fatal("closed IAM roster omitted publishable material or admitted owner-only keys")
		}
	}
	for _, name := range []string{"terrabase-member-ca.pem", "terrabase-member-ca.key", "controller-a-admission.key", "controller-b-admission.key", "controller-c-admission.key"} {
		if !slices.Contains(files, name) {
			t.Fatal("actual closed roster omitted member CA or dedicated admission key")
		}
	}
	invalid := material.Config
	invalid.Cell = "foreign"
	if _, err := bootstrapmaterial.OriginalPublicationSecretNames(invalid); err == nil {
		t.Fatal("invalid material configuration produced an IAM roster")
	}
}
