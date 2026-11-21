package main

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"maps"
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
	interrupt         string
	reached           string
	conflictingVolume string
}

func (b *bindingJourney) checkpoint(w http.ResponseWriter, step string) {
	if b.interrupt == step {
		b.reached = step
		w.Header().Set("X-Journey-Interrupt", "true")
	}
}

type bindingTransport struct {
	cancel context.CancelFunc
}

func (t bindingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := http.DefaultTransport.RoundTrip(r)
	if err == nil && response.Header.Get("X-Journey-Interrupt") == "true" {
		response.Body = &bindingResponse{ReadCloser: response.Body, cancel: t.cancel}
	}
	return response, err
}

type bindingResponse struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *bindingResponse) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
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
	if r.Method == http.MethodGet && kind == "volumes" && len(parts) == 3 {
		for _, volume := range c.resources[kind] {
			if volume["id"] == parts[2] && volume["lifecycleState"] == "PROVISIONING" {
				c.events = append(c.events, "volume-provisioning")
				reply(volume)
				volume["lifecycleState"] = "AVAILABLE"
				return true
			}
		}
	}
	if r.Method == http.MethodGet && kind == "volumeAttachments" && len(parts) == 3 && c.resources[kind][0]["lifecycleState"] == "ATTACHING" {
		b.checkpoint(w, "attachment")
		c.events = append(c.events, "attachment-settling")
		reply(c.resources[kind][0])
		c.resources[kind][0]["lifecycleState"] = "ATTACHED"
		return true
	}
	if r.Method == http.MethodPost && kind == "volumeAttachments" && b.failAttach {
		b.checkpoint(w, "attach")
		http.Error(w, "attach interrupted", http.StatusBadRequest)
		return true
	}
	if r.Method != http.MethodPut || kind != "instances" && kind != "volumes" {
		return false
	}
	c.events = append(c.events, r.Method+" "+kind)
	if kind == "volumes" {
		if b.failTag {
			b.checkpoint(w, "tag")
			http.Error(w, "tag interrupted", http.StatusBadRequest)
			return true
		}
		var old object
		for _, volume := range c.resources["volumes"] {
			if volume["id"] == parts[2] {
				old = volume["freeformTags"].(object)
			}
		}
		must(old != nil, "missing volume to update")
		if old["terrascale-data-instance"] != nil && old["terrascale-data-instance"] != "" {
			w.WriteHeader(http.StatusBadRequest)
			reply(object{"code": "InvalidParameter", "message": "owner tag is already written"})
			return true
		}
		must(r.Header.Get("If-Match") == "journey", "volume claim lacks current ETag")
		b.volumeWrites++
	} else {
		must(c.resources["instances"][0]["lifecycleState"] == "RUNNING", "metadata updated before instance settled")
		must(!slices.ContainsFunc(c.resources["volumeAttachments"], func(a object) bool {
			return a["lifecycleState"] != "ATTACHED" && a["lifecycleState"] != "DETACHED"
		}), "metadata updated before attachment settled")
		must(r.Header.Get("If-Match") == fmt.Sprint(b.instanceETag), "metadata update used stale instance ETag")
		if b.failMetadata {
			b.checkpoint(w, "metadata")
			http.Error(w, "metadata interrupted", http.StatusBadRequest)
			return true
		}
		if b.conflicts > 0 {
			b.checkpoint(w, "conflict")
			b.conflicts--
			b.conflictCount++
			b.instanceETag++
			c.resources["instances"][0]["metadata"].(object)["concurrent"] = "retained"
			if b.conflictingVolume != "" {
				c.resources["instances"][0]["metadata"].(object)[nodeinit.VolumeKey] = b.conflictingVolume
			}
			w.WriteHeader(http.StatusConflict)
			reply(object{"code": "Conflict", "message": "attachment update still in progress"})
			return true
		}
	}
	var update object
	must(json.UnmarshalRead(r.Body, &update) == nil, "decode compute update")
	for _, item := range c.resources[kind] {
		if item["id"] == parts[2] {
			for key, value := range update {
				item[key] = value
			}
			reply(item)
			return true
		}
	}
	panic("missing update resource")
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
	invocation, cancel := context.WithCancel(ctx)
	defer cancel()
	client := &http.Client{Transport: bindingTransport{cancel: cancel}}
	pass.Compute.HTTPClient = client
	pass.Management.HTTPClient = client
	pass.Storage.HTTPClient = client
	return pass.Run(invocation)
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
		c.binding.interrupt = step
		err = applyBinding(ctx, c, pass)
		must(err != nil && c.binding.reached == step, fmt.Sprint("missing interruption after ", step, ": ", err))
		if step == "metadata" || step == "conflict" {
			must(c.binding.volumeWrites == 1 && c.resources["volumes"][0]["freeformTags"].(object)["terrascale-data-instance"] == "pool-node", "owner tag was not written before "+step)
		}
		if step == "conflict" {
			must(c.binding.conflictCount == 1, "interruption did not follow 409")
		}
		c.binding.interrupt = ""
		c.binding.failAttach = false
		c.binding.failTag = false
		c.binding.failMetadata = false
		err = applyBinding(ctx, c, pass)
		must(err == nil, fmt.Sprint("rerun after ", step, ": ", err))
		bound(c)
		must(c.binding.volumeWrites == 1, "rerun rewrote owner tag after "+step)
	}
	fmt.Println("compute binding: failures at attach, attachment settling, tag, metadata and attach->409 all resume without duplicate attachments or tag writes")

	for _, state := range []string{"attached", "metadata-bound"} {
		c, pass = bindingCloud()
		c.binding.failMetadata = true
		c.binding.interrupt = "metadata"
		err = applyBinding(ctx, c, pass)
		must(err != nil && c.binding.reached == "metadata" && c.binding.volumeWrites == 1, "missing written owner before foreign-owner scenario")
		c.binding.interrupt = ""
		c.binding.failMetadata = false
		c.resources["volumes"][0]["freeformTags"].(object)["terrascale-data-instance"] = "different-instance"
		if state == "metadata-bound" {
			c.resources["instances"][0]["metadata"].(object)[nodeinit.VolumeKey] = c.resources["volumes"][0]["id"]
		}
		writes := len(c.events)
		err = applyBinding(ctx, c, pass)
		must(err != nil && strings.Contains(err.Error(), "different-instance") && strings.Contains(err.Error(), "pool-node"), fmt.Sprint("foreign owner accepted: ", err))
		must(len(c.events) == writes, "foreign owner changed cloud resources")
	}
	fmt.Println("compute binding: different attached owner refuses before owner or metadata writes, including metadata already bound")
	computeSelection(ctx)
	computeConflicts(ctx)
}

func poolVolume(c *cloud, pass compute.Pass, name, owner string) object {
	tags := object{}
	for key, value := range pass.Ownership.Stamp(pass.Key("volume", name), 1, "").Freeform {
		tags[key] = value
	}
	tags["terrascale-data-uuid"] = uuid
	if owner != "" {
		tags["terrascale-data-instance"] = owner
	}
	volume := object{"id": "ocid1.volume.oc1.test." + name, "availabilityDomain": "AD", "lifecycleState": "AVAILABLE", "sizeInGBs": 50, "freeformTags": tags}
	c.resources["volumes"] = append(c.resources["volumes"], volume)
	return volume
}

func poolAttachment(c *cloud, volume object, device string) object {
	attachment := object{"id": fmt.Sprintf("attachment-%d", len(c.resources["volumeAttachments"])), "instanceId": "pool-node", "volumeId": volume["id"],
		"device": device, "attachmentType": "paravirtualized", "isReadOnly": false, "isShareable": false, "lifecycleState": "ATTACHED"}
	c.resources["volumeAttachments"] = append(c.resources["volumeAttachments"], attachment)
	return attachment
}

func computeSelection(ctx context.Context) {
	for _, retained := range []int{1, 2, 3} {
		c, pass := bindingCloud()
		for n := 1; n <= retained; n++ {
			poolVolume(c, pass, fmt.Sprintf("data-%d", n), "retired-node")
		}
		if retained == 1 {
			poolVolume(c, pass, "data-2", "")
		}
		before, err := json.Marshal(c.resources["volumes"][:retained], json.Deterministic(true))
		must(err == nil, fmt.Sprint(err))
		err = applyBinding(ctx, c, pass)
		after, marshalErr := json.Marshal(c.resources["volumes"][:retained], json.Deterministic(true))
		must(marshalErr == nil && string(before) == string(after), "retained volumes changed")
		if retained == pass.Max {
			must(err != nil && strings.Contains(err.Error(), "nodes.max allows 3 data volumes, all allocated") && strings.Contains(err.Error(), "retired-node"), fmt.Sprint("allocation beyond nodes.max: ", err))
			must(len(c.resources["volumes"]) == retained && len(c.resources["volumeAttachments"]) == 0 && !slices.Contains(c.events, "POST volumes") &&
				c.resources["instances"][0]["metadata"].(object)[nodeinit.VolumeKey] == nil, "exhausted capacity created, attached or bound a volume")
			continue
		}
		must(err == nil, fmt.Sprint("retained volume blocks capacity below nodes.max: ", err))
		must(len(c.resources["volumes"]) == retained+1 && len(c.resources["volumeAttachments"]) == 1, "incorrect retained-volume capacity")
		selected := c.resources["volumes"][len(c.resources["volumes"])-1]
		must(c.resources["instances"][0]["metadata"].(object)[nodeinit.VolumeKey] == selected["id"], "retained disk selected instead of eligible slot")
	}
	fmt.Println("compute binding: retired-owner slots stay untouched; a later unclaimed slot or a new one below nodes.max is used; at nodes.max the pass refuses without creating a disk")

	for _, allocation := range []string{"duplicate-key", "terminating"} {
		c, pass := bindingCloud()
		poolVolume(c, pass, "data-1", "retired-node")
		want := "nodes.max allows 3 data volumes, all allocated"
		if allocation == "duplicate-key" {
			poolVolume(c, pass, "data-2", "retired-node")
			poolVolume(c, pass, "data-1", "")["id"] = "ocid1.volume.oc1.test.data-1-twin"
			want = "refusing ambiguous data volume identity"
		} else {
			poolVolume(c, pass, "data-2", "")["lifecycleState"] = "TERMINATING"
			poolVolume(c, pass, "data-3", "retired-node")
		}
		before, err := json.Marshal(c.resources["volumes"], json.Deterministic(true))
		must(err == nil, fmt.Sprint(err))
		err = applyBinding(ctx, c, pass)
		after, marshalErr := json.Marshal(c.resources["volumes"], json.Deterministic(true))
		must(err != nil && strings.Contains(err.Error(), want), fmt.Sprint("allocation not counted by OCID for ", allocation, ": ", err))
		must(marshalErr == nil && string(before) == string(after) && len(c.resources["volumes"]) == 3 && len(c.resources["volumeAttachments"]) == 0 &&
			!slices.Contains(c.events, "POST volumes") && c.resources["instances"][0]["metadata"].(object)[nodeinit.VolumeKey] == nil, "ambiguous or terminating allocation created, attached or bound a volume: "+allocation)
	}
	fmt.Println("compute binding: two volumes with one data-1 key refuse before selection; a TERMINATING disk counts toward nodes.max and is never picked")

	c, pass := bindingCloud()
	provisioning := poolVolume(c, pass, "data-1", "")
	provisioning["lifecycleState"] = "PROVISIONING"
	err := applyBinding(ctx, c, pass)
	must(err == nil, fmt.Sprint("provisioning volume did not resume: ", err))
	bound(c)
	must(slices.Contains(c.events, "volume-provisioning") && !slices.Contains(c.events, "POST volumes"), "rerun during PROVISIONING created another disk")
	fmt.Println("compute binding: a rerun while the created disk is PROVISIONING waits for it and binds it without a second disk")

	computeClaims(ctx)

	c, pass = bindingCloud()
	other := poolVolume(c, pass, "data-1", "")
	data := poolVolume(c, pass, "data-3", "pool-node")
	poolAttachment(c, other, "/dev/oracleoci/oraclevdc")
	poolAttachment(c, data, "/dev/oracleoci/oraclevdb")
	metadata := c.resources["instances"][0]["metadata"].(object)
	metadata[nodeinit.VolumeKey], metadata[nodeinit.FormatKey] = data["id"], "false"
	before := maps.Clone(metadata)
	err = applyBinding(ctx, c, pass)
	must(err == nil, fmt.Sprint("secondary attachment changed data binding: ", err))
	must(maps.Equal(metadata, before) && len(c.resources["volumeAttachments"]) == 2 && c.binding.volumeWrites == 0 &&
		!slices.Contains(c.events, "PUT instances") && !slices.Contains(c.events, "POST volumeAttachments"), "secondary volume replaced existing binding")
	must(other["freeformTags"].(object)["terrascale-data-instance"] == nil, "secondary volume was claimed")
	fmt.Println("compute binding: data-3 at the data device and its format refusal survive a sorted data-1 secondary attachment")
}

func computeConflicts(ctx context.Context) {
	for _, conflict := range []string{"metadata", "device", "read-only", "shared"} {
		c, pass := bindingCloud()
		volume := poolVolume(c, pass, "data-1", "")
		attachment := poolAttachment(c, volume, "/dev/oracleoci/oraclevdb")
		metadata := c.resources["instances"][0]["metadata"].(object)
		metadata[nodeinit.VolumeKey] = volume["id"]
		switch conflict {
		case "metadata":
			metadata[nodeinit.VolumeKey] = "ocid1.volume.oc1.test.recorded"
		case "device":
			attachment["device"] = "/dev/oracleoci/oraclevdc"
		case "read-only":
			attachment["isReadOnly"] = true
		case "shared":
			attachment["isShareable"] = true
		}
		before, err := json.Marshal([]any{volume, attachment, metadata}, json.Deterministic(true))
		must(err == nil, fmt.Sprint(err))
		err = applyBinding(ctx, c, pass)
		must(err != nil, "accepted conflicting "+conflict)
		after, marshalErr := json.Marshal([]any{volume, attachment, metadata}, json.Deterministic(true))
		must(marshalErr == nil && string(before) == string(after) && c.binding.volumeWrites == 0 &&
			!slices.Contains(c.events, "PUT instances") && !slices.Contains(c.events, "POST volumeAttachments"), "conflict mutated binding: "+conflict)
	}
	fmt.Println("compute binding: conflicting metadata, wrong device, read-only and shared attachments refuse before owner or metadata writes")

	c, pass := bindingCloud()
	c.binding.conflicts = 1
	c.binding.conflictingVolume = "ocid1.volume.oc1.test.concurrent"
	err := applyBinding(ctx, c, pass)
	must(err != nil && strings.Contains(err.Error(), c.binding.conflictingVolume), fmt.Sprint("409 overwrote conflicting identity: ", err))
	metadata := c.resources["instances"][0]["metadata"].(object)
	must(metadata[nodeinit.VolumeKey] == c.binding.conflictingVolume && metadata[nodeinit.FormatKey] == nil &&
		c.binding.conflictCount == 1 && c.binding.volumeWrites == 1 && len(c.resources["volumeAttachments"]) == 1, "409 retry mutated conflicting identity")
	updates := 0
	for _, event := range c.events {
		if event == "PUT instances" {
			updates++
		}
	}
	must(updates == 1, "409 retry submitted metadata after identity changed")
	fmt.Println("compute binding: metadata OCID changed by a concurrent 409 is preserved; no second metadata update or owner write")
}

func attachedVolumes(c *cloud) []any {
	var ids []any
	for _, attachment := range c.resources["volumeAttachments"] {
		if attachment["instanceId"] == "pool-node" && attachment["lifecycleState"] == "ATTACHED" {
			ids = append(ids, attachment["volumeId"])
		}
	}
	return ids
}

func computeClaims(ctx context.Context) {
	c, pass := bindingCloud()
	unclaimed := poolVolume(c, pass, "data-1", "")
	claimed := poolVolume(c, pass, "data-3", "pool-node")
	poolAttachment(c, claimed, "/dev/oracleoci/oraclevdb")["lifecycleState"] = "DETACHED"
	before, err := json.Marshal(unclaimed, json.Deterministic(true))
	must(err == nil, fmt.Sprint(err))
	err = applyBinding(ctx, c, pass)
	must(err == nil, fmt.Sprint("own claim without attachment did not resume: ", err))
	metadata := c.resources["instances"][0]["metadata"].(object)
	after, err := json.Marshal(unclaimed, json.Deterministic(true))
	must(err == nil && string(before) == string(after), "unclaimed data-1 changed while data-3 holds the claim")
	must(metadata[nodeinit.VolumeKey] == claimed["id"] && metadata[nodeinit.UUIDKey] == uuid && slices.Equal(attachedVolumes(c), []any{claimed["id"]}) &&
		c.binding.volumeWrites == 0 && !slices.Contains(c.events, "POST volumes"), fmt.Sprint("own claim lost to an unclaimed slot: ", metadata, attachedVolumes(c)))
	fmt.Println("compute binding: data-3 claimed by this node with its attachment gone is reattached and bound; unclaimed data-1 stays untouched")

	c, pass = bindingCloud()
	for n, owner := range []string{"fra-node-3", "fra-node-1"} {
		poolAttachment(c, poolVolume(c, pass, fmt.Sprintf("data-%d", n+1), owner), "/dev/oracleoci/oraclevdb")["instanceId"] = owner
	}
	claimed = poolVolume(c, pass, "data-3", "pool-node")
	poolAttachment(c, claimed, "/dev/oracleoci/oraclevdb")
	others, err := json.Marshal(c.resources["volumes"][:2], json.Deterministic(true))
	must(err == nil, fmt.Sprint(err))
	err = applyBinding(ctx, c, pass)
	must(err == nil, fmt.Sprint("fra-node-2 data-3 did not bind: ", err))
	metadata = c.resources["instances"][0]["metadata"].(object)
	after, err = json.Marshal(c.resources["volumes"][:2], json.Deterministic(true))
	must(err == nil && string(others) == string(after), "other nodes' volumes changed")
	must(metadata[nodeinit.VolumeKey] == claimed["id"] && metadata[nodeinit.UUIDKey] == uuid && metadata[nodeinit.FormatKey] == "true" &&
		c.binding.volumeWrites == 0 && len(c.resources["volumes"]) == 3 && len(c.resources["volumeAttachments"]) == 3 &&
		!slices.Contains(c.events, "POST volumes") && !slices.Contains(c.events, "POST volumeAttachments"), fmt.Sprint("fra-node-2 state did not resolve to data-3: ", metadata))
	fmt.Println("compute binding: fra state (data-3 attached and claimed by fra-node-2, metadata empty, data-1 and data-2 bound elsewhere) binds data-3 with no new disk, attachment or owner write")

	for _, conflict := range []string{"two-claims", "metadata-claim"} {
		c, pass = bindingCloud()
		first := poolVolume(c, pass, "data-1", "pool-node")
		if conflict == "metadata-claim" {
			delete(first["freeformTags"].(object), "terrascale-data-instance")
			c.resources["instances"][0]["metadata"].(object)[nodeinit.VolumeKey] = first["id"]
		}
		poolVolume(c, pass, "data-3", "pool-node")
		before, err := json.Marshal([]any{c.resources["volumes"], c.resources["instances"][0]["metadata"]}, json.Deterministic(true))
		must(err == nil, fmt.Sprint(err))
		err = applyBinding(ctx, c, pass)
		must(err != nil && strings.Contains(err.Error(), "refusing conflicting data volume claims"), fmt.Sprint("accepted conflicting claims ", conflict, ": ", err))
		after, err := json.Marshal([]any{c.resources["volumes"], c.resources["instances"][0]["metadata"]}, json.Deterministic(true))
		must(err == nil && string(before) == string(after) && len(c.resources["volumeAttachments"]) == 0 && c.binding.volumeWrites == 0 &&
			!slices.Contains(c.events, "PUT instances") && !slices.Contains(c.events, "POST volumes"), "conflicting claims mutated the cloud: "+conflict)
	}
	fmt.Println("compute binding: two volumes claimed by one node, or a claim other than the recorded volume, refuse before any attach, claim or metadata write")
}
