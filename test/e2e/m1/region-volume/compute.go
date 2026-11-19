package main

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/nodeinit"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/compute"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

type bindingJourney struct {
	settleAfterAttach bool
	settling          bool
	conflicts         int
	conflictCount     int
	failMetadata      bool
	failTag           bool
	failAttach        bool
	volumeWrites      int
	instanceETag      int
}

func (b *bindingJourney) request(c *cloud, w http.ResponseWriter, r *http.Request, parts []string, reply func(any)) bool {
	kind := parts[1]
	if r.Method == http.MethodGet && kind == "instancePools" && len(parts) == 4 {
		reply([]object{{"id": "pool-node", "state": "Running"}})
		return true
	}
	if r.Method == http.MethodGet && kind == "instances" && len(parts) == 3 {
		w.Header().Set("etag", fmt.Sprint(b.instanceETag))
		if b.settling {
			c.events = append(c.events, "instance-settling")
			reply(c.resources["instances"][0])
			c.resources["instances"][0]["lifecycleState"] = "RUNNING"
			b.settling = false
			return true
		}
	}
	if r.Method == http.MethodGet && kind == "volumeAttachments" && len(parts) == 3 && c.resources[kind][0]["lifecycleState"] == "ATTACHING" {
		c.events = append(c.events, "attachment-settling")
		reply(c.resources[kind][0])
		c.resources[kind][0]["lifecycleState"] = "ATTACHED"
		return true
	}
	if r.Method == http.MethodPost && kind == "volumeAttachments" && b.failAttach {
		http.Error(w, "attach interrupted", http.StatusBadRequest)
		return true
	}
	if r.Method != http.MethodPut || kind != "instances" && kind != "volumes" {
		return false
	}
	c.events = append(c.events, r.Method+" "+kind)
	if kind == "volumes" {
		if b.failTag {
			http.Error(w, "tag interrupted", http.StatusBadRequest)
			return true
		}
		old := c.resources["volumes"][0]["freeformTags"].(object)
		if old["terrascale-data-instance"] != nil && old["terrascale-data-instance"] != "" {
			w.WriteHeader(http.StatusBadRequest)
			reply(object{"code": "InvalidParameter", "message": "owner tag is already written"})
			return true
		}
		must(r.Header.Get("If-Match") == "journey", "volume claim lacks current ETag")
		b.volumeWrites++
	} else {
		must(c.resources["instances"][0]["lifecycleState"] == "RUNNING", "metadata updated before instance settled")
		must(c.resources["volumeAttachments"][0]["lifecycleState"] == "ATTACHED", "metadata updated before attachment settled")
		must(r.Header.Get("If-Match") == fmt.Sprint(b.instanceETag), "metadata update used stale instance ETag")
		if b.failMetadata {
			http.Error(w, "metadata interrupted", http.StatusBadRequest)
			return true
		}
		if b.conflicts > 0 {
			b.conflicts--
			b.conflictCount++
			b.instanceETag++
			c.resources["instances"][0]["metadata"].(object)["concurrent"] = "retained"
			w.WriteHeader(http.StatusConflict)
			reply(object{"code": "Conflict", "message": "attachment update still in progress"})
			return true
		}
	}
	var update object
	must(json.UnmarshalRead(r.Body, &update) == nil, "decode compute update")
	for key, value := range update {
		c.resources[kind][0][key] = value
	}
	reply(c.resources[kind][0])
	return true
}

func bindingCloud() (*cloud, compute.Pass) {
	c := newCloud()
	c.binding = &bindingJourney{}
	ownership := ociresource.Ownership{Owner: "journey"}
	key := func(kind, name string) ociresource.Key {
		return ociresource.Key{Region: "fra", Kind: kind, Name: name}
	}
	c.resources["instances"] = []object{{"id": "pool-node", "displayName": "fra-node-2", "availabilityDomain": "AD", "lifecycleState": "RUNNING",
		"freeformTags": ownership.Stamp(key("instance", "node"), 1, "").Freeform, "metadata": object{"unrelated": "retained"}}}
	c.resources["volumes"] = nil
	c.resources["volumeAttachments"] = nil
	return c, compute.Pass{Ownership: ownership, Out: ociresource.Out{Same: io.Discard, Changed: io.Discard}, Nodes: compute.Nodes{
		Label: "fra", Compartment: "cell", Shape: "VM.Standard.A1.Flex", OCPUs: 1, MemoryGB: 6, BootGB: 50, DataGB: 50,
		Min: 1, Max: 3, SubnetID: "subnet", NSGID: "nsg", Places: []compute.Place{{AvailabilityDomain: "AD"}}, Key: key,
		Launch: func(context.Context) (compute.Launch, error) {
			return compute.Launch{ImageID: "image", Metadata: map[string]string{"user_data": "journey"}}, nil
		},
	}}
}

func applyBinding(ctx context.Context, c *cloud, pass compute.Pass) error {
	api := httptest.NewServer(c)
	defer api.Close()
	provider := common.DefaultConfigProvider()
	var err error
	pass.Compute, err = core.NewComputeClientWithConfigurationProvider(provider)
	must(err == nil, fmt.Sprint(err))
	pass.Management, err = core.NewComputeManagementClientWithConfigurationProvider(provider)
	must(err == nil, fmt.Sprint(err))
	pass.Storage, err = core.NewBlockstorageClientWithConfigurationProvider(provider)
	must(err == nil, fmt.Sprint(err))
	pass.Compute.Host = api.URL
	pass.Management.Host = api.URL
	pass.Storage.Host = api.URL
	return pass.Run(ctx)
}

func bound(c *cloud) {
	metadata := c.resources["instances"][0]["metadata"].(object)
	volume := c.resources["volumes"][0]
	must(metadata[nodeinit.VolumeKey] == volume["id"] && metadata[nodeinit.UUIDKey] == volume["freeformTags"].(object)["terrascale-data-uuid"] &&
		metadata[nodeinit.FormatKey] == "true" && metadata["unrelated"] == "retained", fmt.Sprint("incomplete binding: ", metadata))
	must(volume["freeformTags"].(object)["terrascale-data-instance"] == "pool-node", "missing volume owner")
	must(len(c.resources["volumes"]) == 1 && len(c.resources["volumeAttachments"]) == 1, "rerun duplicated volume or attachment")
}

func computeBindings() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c, pass := bindingCloud()
	c.binding.settleAfterAttach = true
	c.binding.conflicts = 1
	err := applyBinding(ctx, c, pass)
	must(err == nil, fmt.Sprint("conflict did not resume: ", err))
	bound(c)
	must(c.binding.conflictCount == 1 && c.binding.volumeWrites == 1 && slices.Contains(c.events, "instance-settling") && slices.Contains(c.events, "attachment-settling"), "missing lifecycle/conflict proof")
	must(c.resources["instances"][0]["metadata"].(object)["concurrent"] == "retained", "conflict retry lost concurrent metadata")
	writes := len(c.events)
	err = applyBinding(ctx, c, pass)
	must(err == nil && len(c.events) == writes, fmt.Sprint("completed bind was not idempotent: ", err, c.events))
	fmt.Println("compute binding: attach settles instance, 409 re-reads ETag and metadata, retry succeeds, completed rerun writes nothing")

	for _, step := range []string{"attach", "attachment", "tag", "metadata", "conflict"} {
		c, pass = bindingCloud()
		c.binding.settleAfterAttach = step == "attachment"
		c.binding.failAttach = step == "attach"
		c.binding.failTag = step == "tag"
		c.binding.failMetadata = step == "metadata"
		if step == "conflict" {
			c.binding.conflicts = 1
		}
		interrupted, stop := context.WithTimeout(ctx, 500*time.Millisecond)
		err = applyBinding(interrupted, c, pass)
		stop()
		must(err != nil, "missing interruption after "+step)
		if step == "conflict" {
			must(c.binding.conflictCount == 1 && strings.Contains(err.Error(), "last OCI conflict"), "interruption did not follow 409")
		}
		c.binding.failAttach = false
		c.binding.failTag = false
		c.binding.failMetadata = false
		err = applyBinding(ctx, c, pass)
		must(err == nil, fmt.Sprint("rerun after ", step, ": ", err))
		bound(c)
		must(c.binding.volumeWrites == 1, "rerun rewrote owner tag after "+step)
	}
	fmt.Println("compute binding: failures at attach, attachment settling, tag, metadata and attach->409 all resume without duplicate attachments or tag writes")

	for _, state := range []string{"detached", "attached", "metadata-bound"} {
		c, pass = bindingCloud()
		c.binding.failMetadata = true
		interrupted, stop := context.WithTimeout(ctx, 500*time.Millisecond)
		_ = applyBinding(interrupted, c, pass)
		stop()
		c.binding.failMetadata = false
		c.resources["volumes"][0]["freeformTags"].(object)["terrascale-data-instance"] = "different-instance"
		if state == "detached" {
			c.resources["volumeAttachments"] = nil
		}
		if state == "metadata-bound" {
			c.resources["instances"][0]["metadata"].(object)[nodeinit.VolumeKey] = c.resources["volumes"][0]["id"]
		}
		writes := len(c.events)
		err = applyBinding(ctx, c, pass)
		must(err != nil && strings.Contains(err.Error(), "different-instance") && strings.Contains(err.Error(), "pool-node"), fmt.Sprint("foreign owner accepted: ", err))
		must(len(c.events) == writes, "foreign owner changed cloud resources")
	}
	fmt.Println("compute binding: different owner refuses before attach or metadata update, including an already attached volume")
}
