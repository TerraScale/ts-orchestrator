package app

import (
	"bytes"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
)

func TestRuntimeWorkerPrivateTransportPinsCAAndRefusesRedirect(t *testing.T) {
	const document = `{"signed":"worker-transport"}`
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/redirect" {
			http.Redirect(writer, request, "/worker-refresh", http.StatusTemporaryRedirect)
			return
		}
		wire, err := io.ReadAll(request.Body)
		if request.Method != http.MethodPost || request.TLS == nil || err != nil || string(wire) != document || request.Header.Get("Content-Type") != "application/json" {
			t.Error("worker transport did not preserve its private signed request")
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(writer, document)
	}))
	defer server.Close()
	bundle := hostenroll.PublicBundle{ControllerEndpoints: []string{strings.TrimPrefix(server.URL, "https://")},
		CAPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))}
	wire, err := postRuntimeWorkerDocument(t.Context(), bundle, "/worker-refresh", []byte(document), http.StatusOK)
	if err != nil || !bytes.Equal(wire, []byte(document)) {
		t.Fatalf("pinned private worker transport: %v", err)
	}
	if _, err := postRuntimeWorkerDocument(t.Context(), bundle, "/redirect", []byte(document), http.StatusOK); err == nil {
		t.Fatal("worker transport followed a redirect")
	}
	bundle.CAPEM = "untrusted"
	if _, err := postRuntimeWorkerDocument(t.Context(), bundle, "/worker-refresh", []byte(document), http.StatusOK); err == nil {
		t.Fatal("worker transport accepted an invalid CA pin")
	}
}
