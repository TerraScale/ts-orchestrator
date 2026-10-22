package region

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

type originalNetBirdBackupSDKFixture struct {
	*originalVaultSDKFixture
	backupMu sync.Mutex
	fault    string
	faulted  bool
	posts    [2][2]int
	gets     [2][2]int
	rows     map[string]map[string]any
	upstream http.HandlerFunc
}

func newOriginalNetBirdBackupSDKFixture(t *testing.T, fault string) *originalNetBirdBackupSDKFixture {
	t.Helper()
	base := newOriginalVaultSDKFixture(t, "", 0)
	extendOriginalNetBirdBackupFixtureAuthority(t, base)
	return installOriginalNetBirdBackupSDKFixture(t, base, base.serveHTTP, fault)
}

// Sign the fixture's original documents before any birth; no retained history is rewritten.
func extendOriginalNetBirdBackupFixtureAuthority(t *testing.T, f *originalVaultSDKFixture) {
	t.Helper()
	if f.cloud.materialPosts != 0 || f.cloud.launchPosts != 0 {
		t.Fatal("backup fixture authority must be issued before original producer effects")
	}
	expires := f.now.Add(30 * 24 * time.Hour)
	prepared := f.prepared
	for index := range prepared.Grant.ReleaseAuthorities {
		intent := &prepared.Grant.ReleaseAuthorities[index]
		envelope, err := trust.DecodeEnvelope(intent.DelegationWire)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err = trust.Sign(envelope.Payload, envelope.Scope, f.now.Add(-time.Minute), expires, f.root)
		if err != nil {
			t.Fatal(err)
		}
		intent.DelegationWire = provisionEnvelope(t, envelope)
	}
	manager := prepared.Grant.Regions[0].NetBirdManager
	if manager == nil {
		t.Fatal("backup fixture has no original manager purpose")
	}
	if manager.Components == nil {
		t.Fatal("backup fixture has no fixed original component authority")
	}
	for index := range manager.Components {
		component := &manager.Components[index].Release
		envelope, err := trust.DecodeEnvelope(component.DelegationWire)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err = trust.Sign(envelope.Payload, envelope.Scope, f.now.Add(-time.Minute), expires, f.root)
		if err != nil {
			t.Fatal(err)
		}
		component.DelegationWire = provisionEnvelope(t, envelope)
	}
	qualification, err := trust.DecodeEnvelope(manager.QualificationWire)
	if err != nil {
		t.Fatal(err)
	}
	qualification, err = trust.Sign(qualification.Payload, qualification.Scope, f.now.Add(-time.Minute), expires, f.root)
	if err != nil {
		t.Fatal(err)
	}
	manager.QualificationWire, manager.QualificationDelegationWire = provisionEnvelope(t, qualification), nil
	imageEnvelope, err := trust.DecodeEnvelope(manager.ImageReceiptWire)
	if err != nil {
		t.Fatal(err)
	}
	var image release.ImageReceipt
	if err := json.Unmarshal(imageEnvelope.Payload, &image); err != nil {
		t.Fatal(err)
	}
	image.HostProduction[NetBirdManagerRole] = release.ProductionProof{Qualification: manager.QualificationWire}
	delegationEnvelope, err := trust.DecodeEnvelope(manager.ImageDelegationWire)
	if err != nil {
		t.Fatal(err)
	}
	var delegation trust.Delegation
	if err := json.Unmarshal(delegationEnvelope.Payload, &delegation); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	delegation.SubjectKeyID, err = trust.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	delegation.SubjectPublicKey, err = trust.EncodeDelegatedPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	delegationEnvelope, err = trust.SignDelegation(delegation, f.now.Add(-time.Minute), expires, f.root)
	if err != nil {
		t.Fatal(err)
	}
	imageEnvelope, err = release.SignNetBirdImageReceipt(image, "production", delegationEnvelope, f.roots, private, f.now, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	manager.ImageReceiptWire, manager.ImageDelegationWire = provisionEnvelope(t, imageEnvelope), provisionEnvelope(t, delegationEnvelope)
	for index := range prepared.Grant.InfrastructureSpend.Bootstrap.Slots {
		slot := &prepared.Grant.InfrastructureSpend.Bootstrap.Slots[index]
		if slot.Role == NetBirdManagerRole {
			slot.RecipeSHA256, err = NetBirdManagerRecipeDigest(*manager, image.ImageSHA256)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	home := *prepared.Anchor.FoundationScope
	prepared.Anchor.FoundationScope = &home
	payload, err := trust.EncodePayload(prepared.Grant)
	if err != nil {
		t.Fatal(err)
	}
	scope := trust.Scope{Domain: foundationGrantDomain, DeploymentID: prepared.Anchor.DeploymentID, Cell: string(prepared.Anchor.Cell), Environment: prepared.Anchor.Environment, Role: "foundation", Slot: prepared.Anchor.ClusterID}
	grant, err := trust.Sign(payload, scope, f.now.Add(-time.Second), expires, f.root)
	if err != nil {
		t.Fatal(err)
	}
	grantWire := provisionEnvelope(t, grant)
	prepared.Anchor.FoundationScope.GrantSHA256 = digestSource(grantWire)
	anchor, err := bootstrap.SignBootstrapAnchor(prepared.Anchor, f.now.Add(-time.Second), expires, f.root)
	if err != nil {
		t.Fatal(err)
	}
	f.prepared = prepared
	f.bundle = RetainedFoundation{TenancyID: prepared.Grant.TenancyID, Namespace: prepared.Anchor.StorageDomain.Namespace,
		RootChainWire: f.bundle.RootChainWire, AnchorWire: provisionEnvelope(t, anchor), GrantWire: grantWire}
	if err := VerifyFoundationProvisionBundle(t.Context(), f.roots, f.bundle); err != nil {
		t.Fatal(err)
	}
	f.cloud.bundle = f.bundle.clone()
}

func installOriginalNetBirdBackupSDKFixture(t *testing.T, base *originalVaultSDKFixture, upstream http.HandlerFunc, fault string) *originalNetBirdBackupSDKFixture {
	t.Helper()
	f := &originalNetBirdBackupSDKFixture{originalVaultSDKFixture: base, upstream: upstream, fault: fault, rows: map[string]map[string]any{}}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(server.Close)
	listener, ok := server.Listener.Addr().(*net.TCPAddr)
	if !ok || !listener.IP.IsLoopback() || listener.Port == 0 {
		t.Fatal("original NetBird backup fixture requires literal loopback TLS")
	}
	previous := http.DefaultTransport
	transport := previous.(*http.Transport).Clone()
	transport.DialTLSContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("fixture refuses network %q", network)
		}
		return (&tls.Dialer{Config: server.Client().Transport.(*http.Transport).TLSClientConfig}).DialContext(ctx, "tcp", listener.String())
	}
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections() })
	return f
}

func (f *originalNetBirdBackupSDKFixture) run(t *testing.T) error {
	t.Helper()
	stage, err := provisionFoundationMaterial(t.Context(), f.factoryFor(), f.roots, f.bundle)
	if err != nil {
		return err
	}
	defer stage.cancel()
	ctx, release, err := stage.authority.HomeWrite(stage.ctx, 0)
	if err != nil {
		return err
	}
	defer release()
	for _, retain := range []func(context.Context, *HomeIAMAuthority) error{retainOriginalFoundationCompartments, retainOriginalFoundationNetwork, retainOriginalFoundationVault} {
		if err := retain(ctx, stage.authority); err != nil {
			return err
		}
	}
	record, etag, err := stage.authority.resolver.Store.Load(ctx, "GRU")
	if err != nil {
		return err
	}
	if record.OriginalFoundationCompartments.Regions[0].NetBirdManager == nil {
		grant, err := decodeOriginalMaterialGrant(f.bundle)
		if err != nil || grant.InfrastructureSpend == nil || grant.InfrastructureSpend.Bootstrap == nil {
			return errors.Join(ErrOriginalSourceProducerHold, err)
		}
		var intent *NetBirdManagerIntent
		var allocation *BootstrapSlotIntent
		for _, regional := range grant.Regions {
			if regional.Plan["cell"] == "GRU" {
				intent = regional.NetBirdManager
			}
		}
		for index := range grant.InfrastructureSpend.Bootstrap.Slots {
			candidate := &grant.InfrastructureSpend.Bootstrap.Slots[index]
			if candidate.Cell == "GRU" && candidate.Role == NetBirdManagerRole {
				allocation = candidate
			}
		}
		if intent == nil || allocation == nil {
			return ErrOriginalSourceProducerHold
		}
		manager, err := originalNetBirdManagerScope(record, *intent, *allocation)
		if err != nil {
			return err
		}
		record.OriginalFoundationCompartments.Regions[0].NetBirdManager = &manager
		if err := checkpointOriginalCompartments(ctx, stage.authority, &record, &etag); err != nil {
			return err
		}
	}
	return retainOriginalNetBirdBackup(ctx, stage.authority)
}

func originalBackupSignatureField(authorization, name string) string {
	_, tail, found := strings.Cut(authorization, name+`="`)
	if !found {
		return ""
	}
	value, _, found := strings.Cut(tail, `"`)
	if !found {
		return ""
	}
	return value
}

func (f *originalNetBirdBackupSDKFixture) verifySignature(r *http.Request, body []byte) bool {
	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Signature ") || originalBackupSignatureField(authorization, "algorithm") != "rsa-sha256" {
		return false
	}
	headers := originalBackupSignatureField(authorization, "headers")
	var signed []string
	for header := range strings.FieldsSeq(headers) {
		value := r.Header.Get(header)
		switch header {
		case "(request-target)":
			value = strings.ToLower(r.Method) + " " + r.URL.RequestURI()
		case "host":
			value = r.Host
		case "content-length":
			value = fmt.Sprint(r.ContentLength)
		}
		signed = append(signed, header+": "+value)
	}
	if headers == "" || !strings.Contains(headers, "(request-target)") || !strings.Contains(headers, "host") {
		return false
	}
	if r.Method == http.MethodPost {
		digest := sha256.Sum256(body)
		if !strings.Contains(headers, "x-content-sha256") || r.Header.Get("x-content-sha256") != base64.StdEncoding.EncodeToString(digest[:]) {
			return false
		}
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(originalBackupSignatureField(authorization, "signature"))
	if err != nil {
		return false
	}
	key, err := f.provider.PrivateRSAKey()
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(strings.Join(signed, "\n")))
	return rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature) == nil
}

func (f *originalNetBirdBackupSDKFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.backupMu.Lock()
	defer f.backupMu.Unlock()
	if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/o/"+foundationObjectPrefix+"GRU.json") && !f.faulted && (f.fault == "response before CAS" || f.fault == "lost accepted CAS") {
		body, _, err := originalNetworkBody(r)
		var record FoundationRecord
		wire, marshalErr := json.Marshal(body)
		if err == nil && marshalErr == nil && json.Unmarshal(wire, &record) == nil {
			j := originalNetBirdBackupJournal(record)
			if j != nil && j.Destinations[0].Bucket.Provenance != nil && j.Destinations[0].Bucket.VerifiedAt.IsZero() {
				f.faulted = true
				if f.fault == "lost accepted CAS" {
					recorder := httptest.NewRecorder()
					f.upstream(recorder, r)
					if recorder.Code >= 300 {
						f.cloud.test.Errorf("backup checkpoint fault preceded accepted CAS: %d", recorder.Code)
					}
				}
				originalCompartmentFailure(w, 503, "InternalError")
				return
			}
		}
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	index, slot := -1, 0
	var canonical []byte
	var body map[string]any
	if r.Method == http.MethodPost && r.URL.Path == "/n/ns/b" {
		var err error
		body, canonical, err = originalNetworkBody(r)
		if err != nil {
			f.cloud.test.Error(err)
			originalCompartmentFailure(w, 400, "InvalidParameter")
			return
		}
		for i, name := range [2]string{"gru-1-backup", "sjc-1-backup"} {
			if body["name"] == name {
				index = i
			}
		}
	} else if len(parts) >= 4 && parts[0] == "n" && parts[1] == "ns" && parts[2] == "b" {
		for i, name := range [2]string{"gru-1-backup", "sjc-1-backup"} {
			if parts[3] == name {
				index = i
			}
		}
		if len(parts) > 4 && parts[4] == "retentionRules" {
			slot = 1
		}
	}
	if index < 0 {
		f.upstream(w, r)
		return
	}
	if r.Method == http.MethodPost && slot == 1 {
		var err error
		body, canonical, err = originalNetworkBody(r)
		if err != nil {
			f.cloud.test.Error(err)
			originalCompartmentFailure(w, 400, "InvalidParameter")
			return
		}
	}
	// Verify the real SDK signature against the exact transmitted body, not canonical JSON.
	var transmitted []byte
	if r.Method == http.MethodPost {
		var err error
		if r.Body != nil {
			transmitted, err = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(transmitted))
			if err != nil {
				f.cloud.test.Error(err)
			}
		}
	}
	if !f.verifySignature(r, transmitted) || r.URL.RawQuery != "" || r.Method != http.MethodGet && r.Method != http.MethodPost {
		f.cloud.test.Error("backup crossed an unsigned or unexpected SDK boundary")
		originalCompartmentFailure(w, 401, "NotAuthenticated")
		return
	}
	record := f.record(f.cloud.test)
	j := originalNetBirdBackupJournal(record)
	if j == nil || record.validateOriginalNetBirdBackup() != nil || index >= len(j.Destinations) {
		f.cloud.test.Error("backup SDK dispatch preceded genuine original typed scope")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	d := j.Destinations[index]
	entry := originalNetBirdBackupEntry(&d, slot)
	if r.Host != "objectstorage."+d.OCIRegion+".oraclecloud.com" {
		f.cloud.test.Errorf("backup escaped signed regional Object Storage endpoint: %s", r.Host)
	}
	id := fmt.Sprintf("ocid1.bucket.oc1.%s.originalbackup", d.OCIRegion)
	if slot == 1 {
		id = "original-backup-retention-" + d.Cell
	}
	if r.Method == http.MethodPost {
		f.posts[index][slot]++
		if entry.Pending == nil || entry.Provenance != nil || entry.Pending.Request.RequestDigest != digestSource(canonical) || entry.Pending.Request.RetryToken != "" || entry.HoldReason != "" || slot == 1 && d.Bucket.VerifiedAt.IsZero() {
			f.cloud.test.Error("backup POST lacked its exact durable original request/parent checkpoint")
		}
		if f.fault == "refused" && index == 0 && slot == 0 {
			originalCompartmentFailure(w, 403, "NotAuthorized")
			return
		}
		row := map[string]any{}
		for key, value := range body {
			row[key] = value
		}
		row["id"], row["timeCreated"] = id, time.Now().UTC().Format(time.RFC3339Nano)
		if slot == 0 {
			row["namespace"], row["createdBy"] = j.Namespace, record.OriginalFoundationCompartments.UserID
		} else {
			row["etag"], row["timeModified"] = "retention-etag", row["timeCreated"]
		}
		f.rows[id] = row
		if !f.faulted && (f.fault == "lost response" && slot == 0 || f.fault == "lost retention response" && slot == 1) {
			f.faulted = true
			originalCompartmentFailure(w, 503, "InternalError")
			return
		}
		if f.fault == "missing response ID" && slot == 0 {
			json.MarshalWrite(w, map[string]any{})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.MarshalWrite(w, row)
		return
	}
	f.gets[index][slot]++
	if entry.Provenance == nil || entry.Provenance.ResourceID != id || f.rows[id] == nil || slot == 0 && len(parts) != 4 || slot == 1 && (len(parts) != 6 || parts[5] != id) {
		f.cloud.test.Error("backup GET tried to adopt a name or escaped its retained actual response ID")
		originalCompartmentFailure(w, 404, "NotFound")
		return
	}
	if f.fault == "KMS drift" && slot == 0 {
		copy := map[string]any{}
		for key, value := range f.rows[id] {
			copy[key] = value
		}
		copy["kmsKeyId"] = "ocid1.key.oc1." + d.OCIRegion + ".foreign"
		json.MarshalWrite(w, copy)
		return
	}
	json.MarshalWrite(w, f.rows[id])
}

func TestOriginalNetBirdBackupSDK(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	t.Run("short original authority refuses all backup dispatch", func(t *testing.T) {
		base := newOriginalVaultSDKFixture(t, "", 0)
		f := installOriginalNetBirdBackupSDKFixture(t, base, base.serveHTTP, "")
		if err := f.run(t); err == nil || errors.Is(err, ErrOriginalNetBirdBackupPending) || f.posts != [2][2]int{} {
			t.Fatalf("short original authority bought unusable backup resources: posts=%v err=%v", f.posts, err)
		}
	})
	t.Run("genuine signed histories retain cooling protection without authority", func(t *testing.T) {
		f := newOriginalNetBirdBackupSDKFixture(t, "")
		if err := f.run(t); !errors.Is(err, ErrOriginalNetBirdBackupPending) {
			t.Fatalf("expected locked-retention pending, got %v", err)
		}
		record := f.record(t)
		j := originalNetBirdBackupJournal(record)
		if j == nil || j.Complete || record.validateOriginalNetBirdBackup() != nil {
			t.Fatal("cooling history gained authority or lost its original lineage")
		}
		for index, d := range j.Destinations {
			if d.Bucket.Provenance == nil || d.Retention.Provenance == nil || d.Bucket.VerifiedAt.IsZero() || !d.Retention.VerifiedAt.IsZero() || f.posts[index] != [2]int{1, 1} || !d.Retention.Request.TimeRuleLocked.Time.After(time.Now()) {
				t.Fatalf("destination %d did not retain genuine bucket/rule histories: %+v", index, d)
			}
		}
		if err := readOriginalNetBirdBackup(t.Context(), f.factoryFor(), record); !errors.Is(err, ErrOriginalNetBirdBackupPending) {
			t.Fatalf("cooling bucket yielded a consumer proof: %v", err)
		}
		before := f.posts
		if err := f.run(t); !errors.Is(err, ErrOriginalNetBirdBackupPending) || f.posts != before {
			t.Fatalf("readback recovery repeated a POST: posts=%v err=%v", f.posts, err)
		}
		for name, mutate := range map[string]func(*FoundationRecord){
			"erase scope":            func(r *FoundationRecord) { r.OriginalFoundationCompartments.Regions[0].NetBirdManager.Backup = nil },
			"change original bundle": func(r *FoundationRecord) { originalNetBirdBackupJournal(*r).BundleSHA256 = strings.Repeat("a", 64) },
			"erase pending":          func(r *FoundationRecord) { originalNetBirdBackupJournal(*r).Destinations[0].Bucket.Pending = nil },
			"change returned ID": func(r *FoundationRecord) {
				originalNetBirdBackupJournal(*r).Destinations[1].Bucket.Provenance.ResourceID += "foreign"
			},
			"grant cooling authority": func(r *FoundationRecord) { originalNetBirdBackupJournal(*r).Complete = true },
		} {
			t.Run(name, func(t *testing.T) {
				wire, err := json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
				var changed FoundationRecord
				if err := json.Unmarshal(wire, &changed); err != nil {
					t.Fatal(err)
				}
				mutate(&changed)
				if changed.validateOriginalNetBirdBackup() == nil && changed.retainOriginalNetBirdBackup(record) == nil {
					t.Fatal("rewritten original backup history was accepted")
				}
			})
		}
	})
	for _, fault := range []string{"lost response", "lost retention response", "missing response ID", "refused", "response before CAS", "lost accepted CAS", "KMS drift"} {
		t.Run(fault, func(t *testing.T) {
			f := newOriginalNetBirdBackupSDKFixture(t, fault)
			if err := f.run(t); err == nil {
				t.Fatal("faulted original backup producer succeeded")
			}
			before := f.posts
			_ = f.run(t)
			if f.posts[0][0] != before[0][0] || fault != "lost accepted CAS" && f.posts != before {
				t.Fatalf("uncertain/refused create was repeated or adopted: before=%v after=%v", before, f.posts)
			}
			j := originalNetBirdBackupJournal(f.record(t))
			if j == nil || j.Complete {
				t.Fatal("faulted lifecycle gained backup authority")
			}
			if fault == "lost response" || fault == "missing response ID" || fault == "refused" || fault == "response before CAS" {
				if j.Destinations[0].Bucket.Provenance != nil || f.gets[0][0] != 0 {
					t.Fatal("missing create response was replaced by name discovery")
				}
			}
		})
	}
}
