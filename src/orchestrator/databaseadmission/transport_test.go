package databaseadmission

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/keylease"
)

func unixTestClient(socket string) *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}}
}
func TestUnixCreateAndScopedOperationPollingOverAuthenticatedNATS(t *testing.T) {
	cluster := newAdmissionJournalCluster(t)
	connection := cluster.connect(t)
	journal := NewMemoryJournal()
	config := pipelineConfig(t, journal)
	pipeline, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := StartAuthority(t.Context(), connection, pipeline)
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	socket := filepath.Join(filepath.Dir(config.CatalogPath), "ingress.sock")
	ingress, err := StartIngress(t.Context(), IngressConfig{Connection: connection, SocketPath: socket, AllowedUID: uint32(os.Geteuid())})
	if err != nil {
		t.Fatal(err)
	}
	defer ingress.Close()
	client := unixTestClient(socket)
	defer client.CloseIdleConnections()
	post := func(path string, request Request) (int, Result) {
		t.Helper()
		data, _ := json.Marshal(request)
		reply, err := client.Post("http://unix/internal/v1/databases/"+path, "application/json", bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		defer reply.Body.Close()
		body, _ := io.ReadAll(reply.Body)
		var value Result
		if (reply.StatusCode == 202 || reply.StatusCode == 200) && json.Unmarshal(body, &value) != nil {
			t.Fatal(string(body))
		}
		return reply.StatusCode, value
	}
	request := journalFixture(t).Request
	code, accepted := post("create", request)
	if code != 202 || accepted.State != "pending" || accepted.DatabaseID == "" {
		t.Fatal(code, accepted)
	}
	lookup := Request{Environment: request.Environment, TenantID: request.TenantID, ProjectID: request.ProjectID, OperationID: request.OperationID}
	code, polled := post("status", lookup)
	if code != 200 || polled.DatabaseID != accepted.DatabaseID || polled.TenantID != lookup.TenantID || polled.ProjectID != lookup.ProjectID {
		t.Fatal(code, polled)
	}
	lookup.ProjectID = "01ARZ3NDEKTSV4RRFFQ69G5FB9"
	if code, _ := post("status", lookup); code != 409 {
		t.Fatal("foreign project found operation", code)
	}
	if _, err := StartIngress(t.Context(), IngressConfig{Connection: connection, SocketPath: socket, AllowedUID: uint32(os.Geteuid())}); err == nil {
		t.Fatal("live socket replaced")
	}
	deniedSocket := filepath.Join(filepath.Dir(config.CatalogPath), "denied.sock")
	denied, err := StartIngress(t.Context(), IngressConfig{Connection: connection, SocketPath: deniedSocket, AllowedUID: uint32(os.Geteuid()) + 1})
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Close()
	deniedClient := unixTestClient(deniedSocket)
	defer deniedClient.CloseIdleConnections()
	data, _ := json.Marshal(request)
	reply, err := deniedClient.Post("http://unix/internal/v1/databases/create", "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	reply.Body.Close()
	if reply.StatusCode != 403 {
		t.Fatal("foreign peer UID reached authority", reply.StatusCode)
	}
}

func TestCiphertextHostDeliveryPrecedesDurableEngineAdmission(t *testing.T) {
	cluster := newAdmissionJournalCluster(t)
	connection := cluster.connect(t)
	config := pipelineConfig(t, NewMemoryJournal())
	record := journalFixture(t)
	if err := keylease.InitializeCatalog(config.CatalogPath); err != nil {
		t.Fatal(err)
	}
	entries := journalWrapped(record)
	socket := filepath.Join(filepath.Dir(config.CatalogPath), "engine.sock")
	listener, err := listenPrivate(socket)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		catalog, err := keylease.ReadCatalog(config.CatalogPath)
		if err != nil || !catalogContainsEntries(catalog, entries) {
			t.Error("engine contacted before wrapped catalog durable", err)
			http.Error(w, "unavailable", 503)
			return
		}
		data, _ := io.ReadAll(r.Body)
		var admission Admission
		if json.Unmarshal(data, &admission) != nil || admission.DatabaseID != record.DatabaseID || admission.KeyVersion != record.KeyVersion || admission.CreatedAt != record.CreatedAt.UnixMilli() {
			t.Error("identity changed")
		}
		data, _ = json.Marshal(map[string]string{"operation_id": admission.OperationID, "database_id": admission.DatabaseID, "state": "admitted"})
		_, _ = w.Write(data)
	})}
	go server.Serve(listener)
	defer server.Close()
	target := record.Targets[0]
	host, err := StartHost(t.Context(), HostConfig{Connection: connection, ServerIdentity: target.ServerIdentity, CatalogPath: config.CatalogPath, EngineSocket: socket, EngineUID: uint32(os.Geteuid()), Environment: record.Request.Environment, Region: target.Region, MemberID: target.MemberID})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	install := RemoteInstall(connection)
	for range 2 {
		if err := install(t.Context(), record, target, entries); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 {
		t.Fatal("immutable retry not delivered")
	}
	entries[0].Binding.ProjectID = "01ARZ3NDEKTSV4RRFFQ69G5FB9"
	if err := install(t.Context(), record, target, entries); err == nil {
		t.Fatal("foreign wrapped key installed")
	}
	if calls != 2 {
		t.Fatal("invalid key reached engine")
	}
}
