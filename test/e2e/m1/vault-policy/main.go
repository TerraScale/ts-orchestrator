package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/regionhost"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	if len(os.Args) != 2 {
		panic("vault policy lane requires binary path")
	}
	if _, err := os.Stat(os.Args[1]); err != nil {
		panic(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	private := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	compartment := "ocid1.compartment.oc1..lane"
	name := "lane-vault"
	original := []string{"broad read grant", "broad manage grant"}
	want := []string{"exact regional read grant"}
	managed := slices.Clone(original)
	retained := []string{}
	copyExists, readDenied, writeDenied := false, false, false
	updates := 0
	policy := func(id, policyName string, statements []string) map[string]any {
		return map[string]any{"id": id, "name": policyName, "compartmentId": compartment, "lifecycleState": "ACTIVE", "statements": statements}
	}
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("etag", "version-1")
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/policies"):
			rows := []any{}
			switch r.URL.Query().Get("name") {
			case name:
				rows = append(rows, policy("managed", name, managed))
			case name + "-transition":
				if copyExists {
					rows = append(rows, policy("retained", name+"-transition", retained))
				}
			default:
				panic("unexpected policy list")
			}
			must(json.NewEncoder(w).Encode(rows))
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/policies/managed"):
			must(json.NewEncoder(w).Encode(policy("managed", name, managed)))
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/policies/retained"):
			if readDenied {
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, "{\"code\":\"NotAuthorized\",\"message\":\"copy unavailable\"}")
				return
			}
			must(json.NewEncoder(w).Encode(policy("retained", name+"-transition", retained)))
		case r.Method == "PUT" && strings.HasSuffix(r.URL.Path, "/policies/managed"):
			updates++
			if r.Header.Get("if-match") != "version-1" {
				panic("policy update must use the read revision")
			}
			if writeDenied {
				w.WriteHeader(http.StatusPreconditionFailed)
				fmt.Fprint(w, "{\"code\":\"NoEtagMatch\",\"message\":\"concurrent policy change\"}")
				return
			}
			body := map[string][]string{}
			must(json.NewDecoder(r.Body).Decode(&body))
			managed = body["statements"]
			must(json.NewEncoder(w).Encode(policy("managed", name, managed)))
		default:
			panic("unexpected policy API: " + r.Method + " " + r.URL.Path)
		}
	}))
	defer endpoint.Close()
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..lane", "ocid1.user.oc1..lane", "us-ashburn-1", "00:11", private, nil)
	client, err := identity.NewIdentityClientWithConfigurationProvider(provider)
	must(err)
	client.Host = endpoint.URL
	for _, mode := range []string{"unchanged", "missing-copy", "incomplete-copy", "copy-read-denied", "copy-active", "update-denied"} {
		managed = slices.Clone(original)
		retained = slices.Clone(original)
		copyExists = mode != "missing-copy" && mode != "unchanged"
		readDenied = mode == "copy-read-denied"
		writeDenied = mode == "update-denied"
		updates = 0
		if mode == "incomplete-copy" {
			retained = retained[:1]
		}
		desired := want
		if mode == "unchanged" {
			desired = original
		}
		_, action, err := regionhost.ReconcileVaultPolicy(ctx, &client, compartment, name, desired)
		success := mode == "unchanged" || mode == "copy-active"
		if success != (err == nil) {
			panic(fmt.Sprintf("%s: action=%s err=%v", mode, action, err))
		}
		if mode == "copy-active" {
			if !slices.Equal(managed, want) || !slices.Equal(retained, original) || updates != 1 {
				panic("narrowing must retain the original effective grants")
			}
		} else if !slices.Equal(managed, original) {
			panic("failed or unchanged reconciliation changed managed access")
		}
		if !success && mode != "update-denied" && updates != 0 {
			panic("read gate failure must not send an update")
		}
		fmt.Printf("ok vault policy %s: error=%t updates=%d; prior access retained\n", mode, err != nil, updates)
	}
	fmt.Println("vault-policy e2e: PASS")
}
