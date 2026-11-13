package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/regionhost"
	"github.com/nats-io/nats-server/v2/server"
)

type object = map[string]any

type cloud struct {
	reads       map[string]int
	mu          sync.Mutex
	resources   map[string][]object
	events      []string
	hideVolumes bool
	volumeLists int
	noListener  bool
	termination bool
	detachment  bool
}

func newCloud() *cloud {
	c := &cloud{resources: map[string][]object{}, reads: map[string]int{}}
	c.resources["instances"] = []object{
		{"id": "keeper", "displayName": "keeper", "lifecycleState": "RUNNING", "timeCreated": "2020-01-01T00:00:00Z", "availabilityDomain": "AD", "faultDomain": "FD-1", "compartmentId": "cell"},
		{"id": "extra", "displayName": "extra", "lifecycleState": "RUNNING", "timeCreated": "2021-01-01T00:00:00Z", "availabilityDomain": "AD", "faultDomain": "FD-2", "compartmentId": "cell", "metadata": object{"terrascale-data-volume": "data"}},
	}
	c.resources["volumes"] = []object{{"id": "data", "displayName": "extra-data", "availabilityDomain": "AD", "lifecycleState": "AVAILABLE", "freeformTags": object{
		"terrascale-managed-by": "ts-orchestrator", "terrascale-resource": "data-volume", "terrascale-host": "extra", "terrascale-data-formatted": "yes",
	}}}
	c.resources["volumeAttachments"] = []object{{"id": "attachment", "instanceId": "extra", "volumeId": "data", "attachmentType": "paravirtualized", "device": "/dev/oracleoci/oraclevdb", "lifecycleState": "ATTACHED"}}
	c.resources["subnets"] = []object{{"id": "subnet", "displayName": "gru-1-host-subnet", "lifecycleState": "AVAILABLE", "cidrBlock": "10.251.0.0/25"}}
	return c
}

func (c *cloud) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("etag", "journey")
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 {
		http.Error(w, "unexpected path", 400)
		return
	}
	kind := parts[1]
	id := ""
	if len(parts) > 2 {
		id = parts[2]
	}
	reply := func(value any) {
		b, err := json.Marshal(value)
		if err != nil {
			panic(err)
		}
		w.Write(b)
	}
	if r.Method == http.MethodGet {
		switch kind {
		case "tenancies":
			reply(object{"id": "tenancy", "homeRegionKey": "GRU"})
			return
		case "compartments":
			name := r.URL.Query().Get("name")
			if name == "" {
				reply([]object{{"id": "cell", "name": "gru-1-control", "lifecycleState": "ACTIVE"}})
			} else {
				cid := "cell"
				if name == "TerraScale" {
					cid = "parent"
				}
				reply([]object{{"id": cid, "name": name, "lifecycleState": "ACTIVE"}})
			}
			return
		case "availabilityDomains":
			reply([]object{{"name": "AD"}})
			return
		case "faultDomains":
			reply([]object{{"name": "FD-1"}, {"name": "FD-2"}, {"name": "FD-3"}})
			return
		case "images":
			reply([]object{{"id": "image", "displayName": "Ubuntu-aarch64"}})
			return
		case "services":
			reply([]object{{"id": "service", "cidrBlock": "all-services"}})
			return
		case "bootVolumeAttachments":
			reply([]object{{"bootVolumeId": "boot", "lifecycleState": "ATTACHED"}})
			return
		case "vnicAttachments":
			if c.noListener {
				reply([]object{})
			} else {
				reply([]object{{"vnicId": "vnic", "lifecycleState": "ATTACHED"}})
			}
			return
		case "vnics":
			reply(object{"id": "vnic", "isPrimary": true, "publicIp": "127.0.0.1"})
			return
		}
		if kind == "volumes" && id == "" {
			c.volumeLists++
			if c.hideVolumes && c.volumeLists > 1 {
				reply([]object{})
				return
			}
		}
		if id != "" {
			for _, item := range c.resources[kind] {
				if item["id"] == id {
					if kind == "instances" && item["lifecycleState"] == "TERMINATING" {
						if c.reads[id] == 0 {
							c.reads[id]++
							c.events = append(c.events, "termination-pending")
							reply(item)
							return
						}
						c.events = append(c.events, "termination-complete")
						item["lifecycleState"] = "TERMINATED"
					}
					if kind == "volumeAttachments" && item["lifecycleState"] == "DETACHING" {
						if c.reads[id] == 0 {
							c.reads[id]++
							c.events = append(c.events, "detach-pending")
							reply(item)
							return
						}
						c.events = append(c.events, "detach-complete")
						item["lifecycleState"] = "DETACHED"
					}
					reply(item)
					return
				}
			}
			http.Error(w, "missing resource", 404)
			return
		}
		items := []object{}
		for _, item := range c.resources[kind] {
			if name := r.URL.Query().Get("displayName"); name != "" && item["displayName"] != name {
				continue
			}
			if asset := r.URL.Query().Get("assetId"); asset != "" && item["assetId"] != asset {
				continue
			}
			items = append(items, item)
		}
		reply(items)
		return
	}
	c.events = append(c.events, r.Method+" "+kind)
	if r.Method == http.MethodDelete {
		for _, item := range c.resources[kind] {
			if item["id"] != id {
				continue
			}
			if kind == "instances" {
				for _, a := range c.resources["volumeAttachments"] {
					if a["instanceId"] == id && a["lifecycleState"] != "DETACHED" {
						c.detachment = true
					}
				}
				item["lifecycleState"] = "TERMINATING"
			} else {
				item["lifecycleState"] = "DETACHING"
			}
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}
	item := object{}
	if err := json.Unmarshal(b, &item); err != nil {
		panic(err)
	}
	if r.Method == http.MethodPut {
		for _, old := range c.resources[kind] {
			if old["id"] == id {
				for k, v := range item {
					old[k] = v
				}
				reply(old)
				return
			}
		}
		http.Error(w, "missing update resource", 400)
		return
	}
	item["id"] = fmt.Sprintf("%s-%d", kind, len(c.resources[kind]))
	item["lifecycleState"] = "AVAILABLE"
	if kind == "instances" {
		for _, old := range c.resources[kind] {
			if old["displayName"] == item["displayName"] && old["lifecycleState"] == "TERMINATING" {
				c.termination = true
			}
		}
		item["lifecycleState"] = "RUNNING"
		item["timeCreated"] = "2022-01-01T00:00:00Z"
	}
	if kind == "volumeAttachments" {
		item["attachmentType"] = "paravirtualized"
		item["lifecycleState"] = "ATTACHED"
	}
	c.resources[kind] = append(c.resources[kind], item)
	reply(item)
}

func must(ok bool, message string) {
	if !ok {
		panic(message)
	}
}

func invoke(c *cloud, args ...string) (string, error) {
	api := httptest.NewServer(c)
	defer api.Close()
	transport := &http.Transport{DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", api.Listener.Addr().String())
	}}
	old := http.DefaultTransport
	http.DefaultTransport = transport
	defer func() {
		http.DefaultTransport = old
		transport.CloseIdleConnections()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var out bytes.Buffer
	err := regionhost.Run(ctx, args, &out)
	return out.String(), err
}

func run() error {
	dir, err := os.MkdirTemp("", "region-volume-journey-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	keyBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	keyPath := filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, keyBytes, 0600); err != nil {
		return err
	}
	config := "[DEFAULT]\ntenancy=ocid1.tenancy.oc1..journey\nuser=ocid1.user.oc1..journey\nfingerprint=00:00\nregion=sa-saopaulo-1\nkey_file=" + keyPath + "\n"
	configPath := filepath.Join(dir, "config")
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		return err
	}
	os.Setenv("OCI_CONFIG_FILE", configPath)
	os.Setenv("HTTPS_PROXY", "")
	os.Setenv("HTTP_PROXY", "")
	os.Setenv("ALL_PROXY", "")
	os.Setenv("NO_PROXY", "*")
	gh := "#!/bin/sh\nif [ \"$2\" = list ]; then printf '[{\"tagName\":\"journey\"}]'; else printf '{\"assets\":[{\"Name\":\"terrascale-orchestrator-linux-arm64\",\"URL\":\"https://example.com/ts-orch\",\"Digest\":\"sha256:" + strings.Repeat("0", 64) + "\"}]}'; fi\n"
	if err := os.WriteFile(filepath.Join(dir, "gh"), []byte(gh), 0700); err != nil {
		return err
	}
	os.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "journey"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), keyBytes)
	if err != nil {
		return err
	}
	listener, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: 4222, NoLog: true, NoSigs: true, TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}})
	if err != nil {
		return err
	}
	go listener.Start()
	defer func() { listener.Shutdown(); listener.WaitForShutdown() }()
	must(listener.ReadyForConnections(5*time.Second), "release listener did not start")
	c := newCloud()
	out, err := invoke(c, "rm", "gru", "--host", "extra", "--dry-run")
	must(err == nil, fmt.Sprint(err))
	must(strings.Contains(out, "plan deleted data-attachment") && strings.Index(out, "plan deleted data-attachment") < strings.Index(out, "plan deleted instance"), out)
	must(len(c.events) == 0, "dry removal wrote cloud state")
	_, err = invoke(c, "rm", "gru", "--host", "extra")
	must(err == nil && !c.detachment, fmt.Sprint("remove before detach: ", err, c.events))
	must(slices.Equal(c.events, []string{"DELETE volumeAttachments", "detach-pending", "detach-complete", "DELETE instances", "termination-pending", "termination-complete"}), fmt.Sprint(c.events))
	out, err = invoke(c, "add", "gru", "--host", "extra", "--dry-run")
	must(err == nil && strings.Contains(out, "plan created data-attachment"), fmt.Sprint(out, err))
	_, err = invoke(c, "add", "gru", "--host", "extra")
	must(err == nil, fmt.Sprint("recreate: ", err))
	fmt.Println("region volume: dry detach precedes termination; immediate create reattaches kept volume")
	for _, state := range []string{"DETACHED", "DETACHING"} {
		c = newCloud()
		c.resources["volumeAttachments"][0]["lifecycleState"] = state
		_, err = invoke(c, "rm", "gru", "--host", "extra")
		must(err == nil && !c.detachment, fmt.Sprint("interrupted detach: ", err, c.events))
	}
	for _, action := range []string{"rm", "add"} {
		c = newCloud()
		c.resources["instances"][1]["lifecycleState"] = "TERMINATING"
		c.resources["volumeAttachments"][0]["lifecycleState"] = "DETACHED"
		_, err = invoke(c, action, "gru", "--host", "extra")
		must(err == nil && !c.termination, fmt.Sprint("interrupted termination: ", err, c.events))
	}
	c = newCloud()
	c.resources["volumeAttachments"][0]["lifecycleState"] = "DETACHED"
	_, err = invoke(c, "add", "gru", "--host", "extra")
	must(err == nil && slices.Contains(c.events, "POST volumeAttachments"), fmt.Sprint("resume detached host: ", err))
	c = newCloud()
	c.hideVolumes = true
	_, err = invoke(c, "add", "gru", "--host", "extra")
	must(err == nil && c.volumeLists == 1, fmt.Sprint("second tag lookup: ", err, c.volumeLists))
	c = newCloud()
	c.resources["volumes"] = nil
	c.resources["volumeAttachments"] = nil
	c.resources["instances"][1]["metadata"] = object{"terrascale-data-volume": "required"}
	c.hideVolumes = true
	_, err = invoke(c, "add", "gru", "--host", "extra")
	must(err == nil && c.volumeLists == 1, fmt.Sprint("created volume lost: ", err, c.volumeLists))
	must(c.resources["volumes"][0]["freeformTags"].(map[string]any)["terrascale-data-formatted"] == "yes", "created volume was not confirmed and tagged")
	c = newCloud()
	c.noListener = true
	c.hideVolumes = true
	_, err = invoke(c, "add", "gru", "--host", "extra")
	must(err != nil && strings.Contains(err.Error(), "host extra state=RUNNING, volume data state=AVAILABLE"), fmt.Sprint("bootstrap falsely succeeded: ", err))
	c = newCloud()
	delete(c.resources["volumes"][0]["freeformTags"].(object), "terrascale-data-formatted")
	_, err = invoke(c, "add", "gru", "--host", "extra")
	must(err != nil && strings.Contains(err.Error(), "requires the terrascale-data-formatted tag"), fmt.Sprint(err))
	must(!slices.Contains(c.events, "POST volumeAttachments"), "untagged volume attached")
	fmt.Println("region volume: interrupted removal resumes; one lookup carries volume to listener; failed boot and untagged adoption refuse success")
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
