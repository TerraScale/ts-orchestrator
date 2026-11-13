package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"github.com/TerraScale/ts-orchestrator/internal/datamount"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/nats-io/nats.go"
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

const serial = "0123456789abcdef0123456789abcdef"

const uuid = "11111111-1111-4111-8111-111111111111"

type object = map[string]any

type cloud struct {
	rules       map[string][]object
	reads       map[string]int
	mu          sync.Mutex
	resources   map[string][]object
	events      []string
	hideVolumes bool
	volumeLists int
	noListener  bool
	termination bool
	failAfter   string
	detachment  bool
}

func newCloud() *cloud {
	c := &cloud{resources: map[string][]object{}, reads: map[string]int{}, rules: map[string][]object{}}
	c.resources["instances"] = []object{
		{"id": "keeper", "displayName": "keeper", "lifecycleState": "RUNNING", "timeCreated": "2020-01-01T00:00:00Z", "availabilityDomain": "AD", "faultDomain": "FD-1", "compartmentId": "cell"},
		{"id": "extra", "displayName": "extra", "lifecycleState": "RUNNING", "timeCreated": "2021-01-01T00:00:00Z", "availabilityDomain": "AD", "faultDomain": "FD-2", "compartmentId": "cell", "metadata": object{"terrascale-data-volume": "ocid1.volume.oc1.test.data", "terrascale-data-may-format": "false"}},
	}
	c.resources["volumes"] = []object{{"id": "ocid1.volume.oc1.test.data", "displayName": "extra-data", "availabilityDomain": "AD", "lifecycleState": "AVAILABLE", "sizeInGBs": 3, "freeformTags": object{
		"terrascale-managed-by": "ts-orchestrator", "terrascale-resource": "data-volume", "terrascale-host": "extra", "terrascale-data-formatted": "yes", "terrascale-data-uuid": uuid, "terrascale-data-instance": "extra", "terrascale-data-serial": serial,
	}}}
	c.resources["volumeAttachments"] = []object{{"id": "attachment", "instanceId": "extra", "volumeId": "ocid1.volume.oc1.test.data", "attachmentType": "paravirtualized", "device": "/dev/oracleoci/oraclevdb", "lifecycleState": "ATTACHED"}}
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

	if kind == "networkSecurityGroups" && len(parts) > 3 {
		if r.Method == http.MethodGet && parts[3] == "securityRules" {
			rules := c.rules[id]
			if rules == nil {
				rules = []object{}
			}
			reply(rules)
			return
		}
		if r.Method == http.MethodPost && len(parts) > 4 && parts[4] == "addSecurityRules" {
			var body struct{ SecurityRules []object }
			if err := json.UnmarshalRead(r.Body, &body); err != nil {
				panic(err)
			}
			for _, rule := range body.SecurityRules {
				rule["id"] = fmt.Sprintf("%s-rule-%d", id, len(c.rules[id]))
				c.rules[id] = append(c.rules[id], rule)
			}
			reply(object{"securityRules": c.rules[id]})
			return
		}
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
					if kind == "instances" && item["lifecycleState"] == "STOPPING" {
						c.events = append(c.events, "stop-complete")
						item["lifecycleState"] = "STOPPED"
					}
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
			if volume := r.URL.Query().Get("volumeId"); volume != "" && item["volumeId"] != volume {
				continue
			}
			if instance := r.URL.Query().Get("instanceId"); instance != "" && item["instanceId"] != instance {
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
	if c.failAfter != "" && slices.Contains(c.events[:len(c.events)-1], c.failAfter) {
		http.Error(w, "interrupted", 400)
		return
	}
	if kind == "instances" && r.Method == http.MethodPost && r.URL.Query().Get("action") != "" {
		must(r.URL.Query().Get("action") == "SOFTSTOP", "removal did not use graceful stop")
		for _, item := range c.resources[kind] {
			if item["id"] == id {
				item["lifecycleState"] = "STOPPING"
				reply(item)
				return
			}
		}
		panic("missing stop instance")
	}
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
				for _, instance := range c.resources["instances"] {
					if instance["id"] == item["instanceId"] && instance["lifecycleState"] != "STOPPED" {
						http.Error(w, "detach while writing", 400)
						return
					}
				}
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
	if kind == "volumes" {
		item["id"] = fmt.Sprintf("ocid1.volume.oc1.test.created%d", len(c.resources[kind]))
	}
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
		for _, instance := range c.resources["instances"] {
			if instance["id"] == item["instanceId"] {
				must(instance["metadata"].(object)["terrascale-data-volume"] == item["volumeId"], "attachment not launch-bound")
			}
		}
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
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
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
	token := "e30." + base64.RawURLEncoding.EncodeToString([]byte(`{"run_id":"123"}`)) + ".signature"
	oidc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		must(r.Header.Get("Authorization") == "bearer local", "missing OIDC authentication")
		fmt.Fprintf(w, `{"value":%q}`, token)
	}))
	defer oidc.Close()
	os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", oidc.URL+"?local=1")
	os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "local")
	listener, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: 4222, NoLog: true, NoSigs: true, Authorization: token, TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}})
	if err != nil {
		return err
	}
	go listener.Start()
	defer func() { listener.Shutdown(); listener.WaitForShutdown() }()
	must(listener.ReadyForConnections(5*time.Second), "release listener did not start")
	conn, err := nats.Connect("tls://127.0.0.1:4222", nats.Token(token), nats.Secure(&tls.Config{InsecureSkipVerify: true}))
	if err != nil {
		return err
	}
	defer conn.Close()
	report := &datamount.Report{Serial: serial, MountPoint: datamount.MountPoint, Device: datamount.Device, UUID: uuid, FilesystemType: "ext4", SizeBytes: 3 * 1024 * 1024 * 1024}
	var reportMu sync.Mutex
	_, err = conn.Subscribe(releasepush.SubjectHealth, func(m *nats.Msg) {
		reportMu.Lock()
		data, marshalErr := json.Marshal(releasepush.Reply{Health: "ok", DataMount: report})
		reportMu.Unlock()
		must(marshalErr == nil, fmt.Sprint(marshalErr))
		m.Respond(data)
	})
	if err != nil {
		return err
	}
	if err := conn.Flush(); err != nil {
		return err
	}
	digest := func(c *cloud) [32]byte {
		b, err := json.Marshal(c.resources["volumes"], json.Deterministic(true))
		must(err == nil, fmt.Sprint(err))
		return sha256.Sum256(b)
	}
	c := newCloud()
	out, err := invoke(c, "rm", "gru", "--host", "extra", "--dry-run")
	must(err == nil && strings.Index(out, "instance-stop") < strings.Index(out, "data-attachment") && strings.Index(out, "data-attachment") < strings.Index(out, "plan deleted instance"), fmt.Sprint(out, err))
	must(len(c.events) == 0, "dry removal changed cloud")
	for _, state := range []string{"RUNNING", "STOPPING", "STOPPED", "DETACHING", "DETACHED", "TERMINATING"} {
		c = newCloud()
		if state == "DETACHING" || state == "DETACHED" {
			c.resources["instances"][1]["lifecycleState"] = "STOPPED"
			c.resources["volumeAttachments"][0]["lifecycleState"] = state
		} else {
			c.resources["instances"][1]["lifecycleState"] = state
		}
		if state == "TERMINATING" {
			c.resources["volumeAttachments"][0]["lifecycleState"] = "DETACHED"
		}
		before := digest(c)
		_, err = invoke(c, "rm", "gru", "--host", "extra")
		must(err == nil && !c.detachment, fmt.Sprint(state, err, c.events))
		must(digest(c) == before, "removal changed volume or backup data")
		must(c.resources["instances"][1]["lifecycleState"] == "TERMINATED", fmt.Sprint(c.events))
	}
	fmt.Println("region volume: RUNNING -> SOFTSTOP -> STOPPING -> STOPPED -> DETACHING -> DETACHED -> TERMINATING -> TERMINATED; interrupted states resume, volumes unchanged")
	for _, state := range []string{"STOPPING", "STOPPED"} {
		c = newCloud()
		c.resources["instances"][1]["lifecycleState"] = state
		before := digest(c)
		_, err = invoke(c, "add", "gru", "--host", "extra")
		must(err != nil && strings.Contains(err.Error(), "finish or abandon"), fmt.Sprint(err))
		must(digest(c) == before && !slices.Contains(c.events, "POST volumeAttachments") && !slices.Contains(c.events, "POST instances"), "add restarted removal")
	}
	for _, difference := range []string{"missing", "uuid", "size", "device", "mountpoint", "filesystem", "serial", "serial-empty"} {
		reportMu.Lock()
		saved := *report
		switch difference {
		case "missing":
			report = nil
		case "uuid":
			report.UUID = "22222222-2222-4222-8222-222222222222"
		case "serial":
			report.Serial = "fedcba9876543210fedcba9876543210"
		case "serial-empty":
			report.Serial = ""
		case "size":
			report.SizeBytes++
		case "device":
			report.Device = "/dev/boot"
		case "mountpoint":
			report.MountPoint = "/"
		case "filesystem":
			report.FilesystemType = "xfs"
		}
		reportMu.Unlock()
		c = newCloud()
		before := digest(c)
		_, err = invoke(c, "add", "gru", "--host", "extra")
		must(err != nil, "accepted mount mismatch "+difference)
		must(digest(c) == before, "mount mismatch changed volume")
		reportMu.Lock()
		report = &saved
		reportMu.Unlock()
	}
	fmt.Println("region volume: answering host without mount, UUID/serial/size/device/mountpoint/filesystem mismatches refuse unchanged")
	c = newCloud()
	before := digest(c)
	_, err = invoke(c, "add", "gru", "--host", "extra")
	must(err == nil, fmt.Sprint("matching report: ", err))
	must(digest(c) == before, "matching adopted mount rewrote volume")
	c = newCloud()
	delete(c.resources["volumes"][0]["freeformTags"].(object), "terrascale-data-serial")
	_, err = invoke(c, "add", "gru", "--host", "extra")
	must(err == nil && c.resources["volumes"][0]["freeformTags"].(object)["terrascale-data-serial"] == serial, fmt.Sprint("adoption serial backfill: ", err))
	fmt.Println("region volume: serial mismatch adoption refuses unchanged; UUID-only adoption records serial after full match")
	c = newCloud()
	c.resources["instances"][1]["metadata"] = object{"terrascale-data-volume": "created-before-interruption", "terrascale-data-may-format": "true"}
	c.resources["volumeAttachments"][0]["lifecycleState"] = "DETACHED"
	_, err = invoke(c, "add", "gru", "--host", "extra")
	must(err != nil && !slices.Contains(c.events, "POST volumeAttachments"), fmt.Sprint("stale formatting instance adopted another volume: ", err, c.events))
	fmt.Println("region volume: interrupted formatting instance cannot attach adopted replacement volume")
	for _, tag := range []string{"terrascale-data-formatted", "terrascale-data-uuid"} {
		c = newCloud()
		delete(c.resources["volumes"][0]["freeformTags"].(object), tag)
		before := digest(c)
		_, err = invoke(c, "add", "gru", "--host", "extra")
		must(err != nil && !slices.Contains(c.events, "POST volumeAttachments") && digest(c) == before, fmt.Sprint(err))
	}
	c = newCloud()
	c.resources["volumeAttachments"][0]["lifecycleState"] = "DETACHED"
	c.resources["instances"][1]["lifecycleState"] = "TERMINATED"
	_, err = invoke(c, "add", "gru", "--host", "extra")
	must(err == nil, fmt.Sprint("adopted replacement: ", err))
	launched := c.resources["instances"][2]
	must(launched["metadata"].(object)["terrascale-data-may-format"] == "false", "adopted launch granted format")
	must(c.resources["volumes"][0]["freeformTags"].(object)["terrascale-data-instance"] == launched["id"], "missing instance binding")
	fmt.Println("region volume: adoption needs initialised UUID tags; replacement launch denies format and binds before attachment")

	c = newCloud()
	c.resources["instances"][1]["lifecycleState"] = "TERMINATED"
	c.resources["volumes"] = nil
	c.resources["volumeAttachments"] = nil
	reportMu.Lock()
	report.SizeBytes = 100 * 1024 * 1024 * 1024
	reportMu.Unlock()
	_, err = invoke(c, "add", "gru", "--host", "extra")
	must(err == nil, fmt.Sprint("new volume: ", err))
	fresh := c.resources["volumes"][0]
	tags := fresh["freeformTags"].(object)
	must(tags["terrascale-data-formatted"] == "yes" && tags["terrascale-data-uuid"] == uuid && tags["terrascale-data-serial"] == serial, "fresh format report not recorded")
	must(c.resources["instances"][2]["metadata"].(object)["terrascale-data-may-format"] == "true", "new-volume launch lacks permission")
	fmt.Println("region volume: only API creation in this invocation grants launch permission; full mount match records initialised UUID and serial")
	c = newCloud()
	c.resources["instances"][1]["lifecycleState"] = "TERMINATED"
	c.resources["volumes"] = nil
	c.resources["volumeAttachments"] = nil
	c.failAfter = "POST instances"
	_, err = invoke(c, "add", "gru", "--host", "extra")
	must(err != nil && len(c.resources["instances"]) == 3 && !slices.Contains(c.events, "POST volumeAttachments"), "interruption did not leave launch-bound waiting instance")
	c.failAfter = ""
	c.events = nil
	c.resources["volumes"][0]["freeformTags"].(object)["terrascale-host"] = "retained-original"
	adopted := newCloud().resources["volumes"][0]
	adopted["id"] = "ocid1.volume.oc1.test.adopted"
	adopted["freeformTags"].(object)["terrascale-data-instance"] = ""
	c.resources["volumes"] = append(c.resources["volumes"], adopted)
	before = digest(c)
	_, err = invoke(c, "add", "gru", "--host", "extra")
	must(err != nil && strings.Contains(err.Error(), "discovered ocid1.volume.oc1.test.adopted") && !slices.Contains(c.events, "POST volumeAttachments"), fmt.Sprint("interrupted then adopted: ", err, c.events))
	must(c.resources["instances"][2]["lifecycleState"] == "TERMINATED" && digest(c) == before, "stale format instance reused or volumes changed")
	reportMu.Lock()
	report.SizeBytes = 3 * 1024 * 1024 * 1024
	reportMu.Unlock()
	_, err = invoke(c, "add", "gru", "--host", "extra")
	must(err == nil, fmt.Sprint("replace stale format instance: ", err))
	must(c.resources["instances"][3]["metadata"].(object)["terrascale-data-may-format"] == "false", "replacement granted stale permission")
	fmt.Println("region volume: exact interrupted launch then adopted disk refuses attachment, terminates stale instance, replaces without format permission")
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
