package materialsource

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

func materialSourceAnchor(t *testing.T) (bootstrap.VerifiedBootstrapAnchor, bootstrap.HistoricalBootstrapAnchor,
	trust.Keyring, ed25519.PrivateKey, []byte,
) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rootPublic, rootPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	ledgerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ledgerID, err := trust.KeyID(ledgerPublic)
	if err != nil {
		t.Fatal(err)
	}
	ledgerWire, err := trust.EncodeDelegatedPublicKey(ledgerPublic)
	if err != nil {
		t.Fatal(err)
	}
	slots := []string{"controller-a", "controller-b", "controller-c"}
	capabilities := make([]trust.Capability, 0, 5)
	for _, domain := range []string{"bootstrap-slot-head", "bootstrap-intent", "bootstrap-result", "bootstrap-candidate", "bootstrap-progress"} {
		capabilities = append(capabilities, trust.Capability{Domain: domain, DeploymentID: "0000000000F9PR1WNVDTEXS31Z",
			Cell: "GRU", Environment: "production", Role: "controller", Slots: slices.Clone(slots), Actions: []string{"sign"}})
	}
	grant, err := trust.SignDelegation(trust.Delegation{SchemaVersion: trust.SchemaVersion,
		SubjectKeyID: ledgerID, SubjectPublicKey: ledgerWire, Capabilities: capabilities},
		now.Add(-time.Hour), now.Add(24*time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	grantWire, err := trust.EncodeEnvelope(grant)
	if err != nil {
		t.Fatal(err)
	}
	intentWire, err := trust.EncodePayload(oci.RegionIntent{SchemaVersion: 1, Generation: 4,
		BootstrapRegion: oci.RegionGRU, Regions: []oci.RegionMapping{{Cell: oci.RegionGRU, OCIRegion: "sa-saopaulo-1"}}})
	if err != nil {
		t.Fatal(err)
	}
	intentDigest := sha256.Sum256(intentWire)
	anchor := bootstrap.BootstrapAnchor{SchemaVersion: bootstrap.BootstrapAnchorSchemaVersion,
		DeploymentID: "0000000000F9PR1WNVDTEXS31Z", Environment: "production", ClusterID: "0000000000RMSAJ9B0JFV7ESHN", Cell: oci.RegionGRU,
		OCIRegion: "sa-saopaulo-1", ControllerSlots: slots, LedgerDelegationWire: grantWire,
		StorageDomain: bootstrap.StorageDomain{Namespace: "namespace-a", LedgerBucket: "ledger-bucket",
			LedgerKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.ledger", HeadBucket: "gru-1-head",
			HeadKMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.head", Prefix: "private/bootstrap"},
		InitialRegionIntentGeneration: 4, InitialRegionIntentSHA256: hex.EncodeToString(intentDigest[:]),
		InitialRegionIntentWire: intentWire}
	envelope, err := bootstrap.SignBootstrapAnchor(anchor, now.Add(-time.Minute), now.Add(time.Hour), rootPrivate)
	if err != nil {
		t.Fatal(err)
	}
	expected := bootstrap.BootstrapAnchorExpectation{DeploymentID: anchor.DeploymentID, Environment: anchor.Environment, Cell: anchor.Cell}
	current, err := bootstrap.VerifyBootstrapAnchor(envelope, roots, expected, now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	historical, err := bootstrap.VerifyHistoricalBootstrapAnchor(envelope, roots, expected, now, bootstrap.BootstrapAnchorTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	anchorWire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return current, historical, roots, rootPrivate, anchorWire
}

type materialProtocolSecret struct {
	ID, Name, Content, Token string
	Target                   bootstrapmaterial.VaultTarget
}
type materialProtocol struct {
	mu                sync.Mutex
	requestMu         sync.Mutex
	requests          map[string]int
	startedAt         time.Time
	lastProgressAt    time.Time
	directory         string
	target            bootstrapmaterial.VaultTarget
	creates           int
	loseCreate        bool
	loseSourceCreate  bool
	hiddenSourceReads int
	sourceCreates     int
	policies          map[string]identity.Policy
	founders          map[string]http.Handler
	interceptObject   func(http.ResponseWriter, *http.Request) bool
	interceptIAM      func(http.ResponseWriter, *http.Request) bool
}

func (server *materialProtocol) recordRequest(r *http.Request) {
	route := r.URL.Path
	if strings.HasPrefix(route, "/n/") {
		route = "/n/.../object"
		if strings.Contains(r.URL.Path, "/bootstrap/v2/material-source/") {
			route = "/n/.../material-source"
		} else if strings.HasSuffix(r.URL.Path, "/iam-lease.json") {
			route = "/n/.../iam-lease"
		}
	} else {
		parts := strings.Split(strings.Trim(route, "/"), "/")
		route = "/" + strings.Join(parts[:min(2, len(parts))], "/")
	}
	server.requestMu.Lock()
	defer server.requestMu.Unlock()
	if server.requests == nil {
		server.requests = map[string]int{}
	}
	server.requests[r.Method+" "+route]++
}

func (server *materialProtocol) logProgress(t *testing.T, phase string) {
	t.Helper()
	server.requestMu.Lock()
	defer server.requestMu.Unlock()
	now := time.Now()
	if server.startedAt.IsZero() {
		server.startedAt, server.lastProgressAt = now, now
	}
	t.Logf("source phase=%s elapsed=%s phase_elapsed=%s requests=%v", phase,
		now.Sub(server.startedAt), now.Sub(server.lastProgressAt), server.requests)
	server.lastProgressAt = now
}

func (server *materialProtocol) objectPath(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(server.directory, hex.EncodeToString(sum[:]))
}
func (server *materialProtocol) put(key string, body []byte) error {
	return os.WriteFile(server.objectPath(key), body, 0o600)
}
func (server *materialProtocol) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Founder handlers also serve a separate metadata endpoint; count them there.
	if !strings.HasPrefix(r.URL.Path, "/20160918/") {
		server.recordRequest(r)
	}
	if server.interceptObject != nil && server.interceptObject(w, r) {
		return
	}
	if strings.HasPrefix(r.URL.Path, "/20160918/") {
		var handler http.Handler
		server.mu.Lock()
		for token, candidate := range server.founders {
			if strings.Contains(r.Header.Get("Authorization"), token) {
				handler = candidate
				break
			}
		}
		server.mu.Unlock()
		if handler != nil {
			handler.ServeHTTP(w, r)
			return
		}
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("Authorization") == "" {
		w.WriteHeader(401)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/n" {
		io.WriteString(w, `"namespace-a"`)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/n/namespace-a/b/gru-1-head" {
		json.MarshalWrite(w, objectstorage.Bucket{Id: new("ocid1.bucket.oc1.sa-saopaulo-1.head"), Name: new("gru-1-head"), Namespace: new("namespace-a"), KmsKeyId: new("ocid1.key.oc1.sa-saopaulo-1.head"), CompartmentId: new("ocid1.compartment.oc1..control")})
		return
	}
	if strings.HasPrefix(r.URL.Path, "/n/") {
		bucketKMS := "ocid1.key.oc1.sa-saopaulo-1.head"
		switch {
		case strings.Contains(r.URL.Path, "/b/ledger-bucket/o/"):
			bucketKMS = "ocid1.key.oc1.sa-saopaulo-1.ledger"
		case strings.Contains(r.URL.Path, "/b/sfo-ledger/o/"):
			bucketKMS = "ocid1.key.oc1.us-sanjose-1.ledger"
		case strings.Contains(r.URL.Path, "/b/sfo-1-head/o/"):
			bucketKMS = "ocid1.key.oc1.us-sanjose-1.head"
		}
		old, err := os.ReadFile(server.objectPath(r.URL.Path))
		etag := digestWire(old)
		if r.Method == http.MethodGet {
			if err != nil {
				w.WriteHeader(404)
				io.WriteString(w, `{"code":"ObjectNotFound","message":"absent"}`)
				return
			}
			info, err := os.Stat(server.objectPath(r.URL.Path))
			if err != nil {
				w.WriteHeader(500)
				return
			}
			w.Header().Set("etag", etag)
			w.Header().Set("Content-Length", strconv.Itoa(len(old)))
			w.Header().Set("Last-Modified", info.ModTime().UTC().Format(http.TimeFormat))
			w.Header().Set("opc-sse-kms-key-id", bucketKMS)
			w.Write(old)
			return
		}
		if r.Method != http.MethodPut {
			w.WriteHeader(405)
			return
		}
		if r.Header.Get("if-none-match") == "*" && err == nil || r.Header.Get("if-match") != "" && (err != nil || r.Header.Get("if-match") != etag) {
			w.WriteHeader(412)
			io.WriteString(w, `{"code":"PreconditionFailed","message":"changed"}`)
			return
		}
		explicitKMS := strings.Contains(r.URL.Path, "/bootstrap/v2/material-source/") || strings.HasSuffix(r.URL.Path, "/iam-lease.json")
		kms := r.Header.Get("opc-sse-kms-key-id")
		if r.Header.Get("if-none-match") == "" && r.Header.Get("if-match") == "" || explicitKMS && kms != bucketKMS || kms != "" && kms != bucketKMS {
			w.WriteHeader(400)
			return
		}
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			w.WriteHeader(400)
			return
		}
		if err := server.put(r.URL.Path, body); err != nil {
			w.WriteHeader(500)
			return
		}
		if r.Header.Get("if-none-match") == "*" && strings.Contains(r.URL.Path, "/bootstrap/v2/material-source/") {
			server.sourceCreates++
		}
		w.Header().Set("etag", digestWire(body))
		return
	}
	var response any
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/secrets"):
		var details struct {
			CompartmentID string `json:"compartmentId"`
			VaultID       string `json:"vaultId"`
			KeyID         string `json:"keyId"`
			Name          string `json:"secretName"`
			Content       struct {
				Content string `json:"content"`
			} `json:"secretContent"`
		}
		if json.UnmarshalRead(r.Body, &details) != nil || details.CompartmentID != server.target.CompartmentOCID || details.VaultID != server.target.VaultOCID || details.KeyID != server.target.KMSKeyOCID || r.Header.Get("opc-retry-token") == "" {
			w.WriteHeader(400)
			return
		}
		if strings.Contains(r.Header.Get("Authorization"), "ocid1.user.oc1..peer") && strings.HasPrefix(details.Name, "ts-bootstrap-source-") {
			w.WriteHeader(403)
			io.WriteString(w, `{"code":"NotAuthorized","message":"founder source create denied"}`)
			return
		}
		if body, err := os.ReadFile(server.objectPath("token-" + r.Header.Get("opc-retry-token"))); err == nil {
			var secret materialProtocolSecret
			json.Unmarshal(body, &secret)
			json.MarshalWrite(w, ocivault.Secret{Id: new(secret.ID)})
			return
		}
		if _, err := os.ReadFile(server.objectPath("name-" + details.Name)); err == nil {
			w.WriteHeader(409)
			io.WriteString(w, `{"code":"Conflict","message":"secret exists"}`)
			return
		}
		server.creates++
		secret := materialProtocolSecret{ID: fmt.Sprintf("ocid1.vaultsecret.oc1.%s.secret%d", strings.Split(server.target.VaultOCID, ".")[3], server.creates), Target: server.target, Name: details.Name, Content: details.Content.Content, Token: r.Header.Get("opc-retry-token")}
		wire, _ := json.Marshal(secret)
		if server.put("secret-"+secret.ID, wire) != nil || server.put("name-"+secret.Name, wire) != nil || server.put("token-"+secret.Token, wire) != nil {
			w.WriteHeader(500)
			return
		}
		if server.loseSourceCreate && strings.HasPrefix(secret.Name, "ts-bootstrap-source-") {
			server.loseSourceCreate = false
			server.hiddenSourceReads = 2
			w.WriteHeader(500)
			io.WriteString(w, `{"code":"InternalError","message":"committed source response lost"}`)
			return
		}
		if server.loseCreate && !strings.HasPrefix(secret.Name, "ts-bootstrap-source-") {
			server.loseCreate = false
			w.WriteHeader(500)
			io.WriteString(w, `{"code":"InternalError","message":"committed response lost"}`)
			return
		}
		response = ocivault.Secret{Id: new(secret.ID)}
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/secrets"):
		body, err := os.ReadFile(server.objectPath("name-" + r.URL.Query().Get("name")))
		items := []ocivault.SecretSummary{}
		if err == nil {
			var secret materialProtocolSecret
			json.Unmarshal(body, &secret)
			items = append(items, ocivault.SecretSummary{Id: new(secret.ID), SecretName: new(secret.Name), CompartmentId: new(secret.Target.CompartmentOCID), VaultId: new(secret.Target.VaultOCID), LifecycleState: ocivault.SecretSummaryLifecycleStateActive})
		}
		response = items
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/secretbundles/actions/getByName"):
		if r.URL.Query().Get("versionNumber") != "1" {
			w.WriteHeader(400)
			return
		}
		if strings.HasPrefix(r.URL.Query().Get("secretName"), "ts-bootstrap-source-") && server.hiddenSourceReads > 0 {
			server.hiddenSourceReads--
			w.WriteHeader(404)
			io.WriteString(w, `{"code":"SecretNotFound","message":"not visible yet"}`)
			return
		}
		body, err := os.ReadFile(server.objectPath("name-" + r.URL.Query().Get("secretName")))
		if err != nil {
			w.WriteHeader(404)
			io.WriteString(w, `{"code":"SecretNotFound","message":"absent"}`)
			return
		}
		var secret materialProtocolSecret
		json.Unmarshal(body, &secret)
		if strings.Contains(r.Header.Get("Authorization"), "ocid1.user.oc1..peer") && strings.HasPrefix(secret.Name, "ts-bootstrap-source-") {
			w.WriteHeader(403)
			io.WriteString(w, `{"code":"NotAuthorized","message":"founder source denied"}`)
			return
		}
		response = ocisecrets.SecretBundle{SecretId: new(secret.ID), VersionNumber: new(int64(1)), SecretBundleContent: ocisecrets.Base64SecretBundleContentDetails{Content: new(secret.Content)}}
	case strings.Contains(r.URL.Path, "/secretbundles/"):
		_, id, _ := strings.Cut(r.URL.Path, "/secretbundles/")
		body, err := os.ReadFile(server.objectPath("secret-" + id))
		if err != nil {
			w.WriteHeader(404)
			return
		}
		var secret materialProtocolSecret
		json.Unmarshal(body, &secret)
		if strings.Contains(r.Header.Get("Authorization"), "ocid1.user.oc1..peer") && strings.HasPrefix(secret.Name, "ts-bootstrap-source-") {
			w.WriteHeader(403)
			io.WriteString(w, `{"code":"NotAuthorized","message":"founder source denied"}`)
			return
		}
		response = ocisecrets.SecretBundle{SecretId: new(id), VersionNumber: new(int64(1)), SecretBundleContent: ocisecrets.Base64SecretBundleContentDetails{Content: new(secret.Content)}}
	case strings.Contains(r.URL.Path, "/secrets/"):
		_, id, _ := strings.Cut(r.URL.Path, "/secrets/")
		body, err := os.ReadFile(server.objectPath("secret-" + id))
		if err != nil {
			w.WriteHeader(404)
			return
		}
		var secret materialProtocolSecret
		json.Unmarshal(body, &secret)
		response = ocivault.Secret{Id: new(id), SecretName: new(secret.Name), CompartmentId: new(secret.Target.CompartmentOCID), VaultId: new(secret.Target.VaultOCID), KeyId: new(secret.Target.KMSKeyOCID), LifecycleState: ocivault.SecretLifecycleStateActive, CurrentVersionNumber: new(int64(1))}
	default:
		w.WriteHeader(404)
		return
	}
	json.MarshalWrite(w, response)
}
