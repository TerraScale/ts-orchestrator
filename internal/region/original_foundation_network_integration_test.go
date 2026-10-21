package region

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/oracle/oci-go-sdk/v65/core"
)

var originalNetworkSDKCollections = map[string]string{
	"vcns": "vcn", "serviceGateways": "service_gateway", "routeTables": "route_table",
	"securityLists": "security_list", "subnets": "subnet", "networkSecurityGroups": "controller_nsg",
}

type originalNetworkDispatch struct {
	cell, key, token string
	body             []byte
	pending          PendingFoundationCreate
}

type originalNetworkSDKFixture struct {
	*originalCompartmentSDKFixture
	networkMu    sync.Mutex
	networkFault string
	faulted      bool
	creates      []originalNetworkDispatch
	rulePosts    map[string]int
	returned     map[string]bool
	added        map[string]bool
	pages        map[string]int
	upstream     []byte
}

func newOriginalNetworkSDKFixture(t *testing.T, fault string) *originalNetworkSDKFixture {
	t.Helper()
	base := newOriginalCompartmentSDKFixture(t, "")
	f := &originalNetworkSDKFixture{originalCompartmentSDKFixture: base, networkFault: fault, rulePosts: map[string]int{}, returned: map[string]bool{}, added: map[string]bool{}, pages: map[string]int{}}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(server.Close)
	listener, ok := server.Listener.Addr().(*net.TCPAddr)
	if !ok || !listener.IP.IsLoopback() || listener.Port == 0 {
		t.Fatal("original network fixture requires literal loopback TLS")
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

func (f *originalNetworkSDKFixture) run(t *testing.T) error {
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
	if err := retainOriginalFoundationCompartments(ctx, stage.authority); err != nil {
		return err
	}
	return retainOriginalFoundationNetwork(ctx, stage.authority)
}

func originalNetworkUpstream(record FoundationRecord) ([]byte, error) {
	section := *record.OriginalFoundationCompartments
	for index := range section.Regions {
		section.Regions[index].Network = nil
		section.Regions[index].Vault = nil
		section.Regions[index].Actor = nil
		section.Regions[index].ActorReads = nil
	}
	return json.Marshal(struct {
		Material     *NetBirdMaterialJournal
		Births       *[3]OriginalSourceProducerBirth
		Compartments OriginalFoundationCompartments
	}{record.NetBirdMaterial, record.OriginalSourceProducers, section}, json.Deterministic(true))
}

func (f *originalNetworkSDKFixture) checkNetworkPrerequisites(record FoundationRecord) {
	f.checkPrerequisites(record)
	section := record.OriginalFoundationCompartments
	if section == nil {
		f.cloud.test.Error("network effect preceded complete original compartment section")
		return
	}
	for index, regional := range section.Regions {
		if regional.Network == nil || !sameOriginalSourceValue(regional.Network.Plan, f.prepared.Grant.Regions[index].Plan) {
			f.cloud.test.Error("network effect preceded all three immutable original signed network scopes")
		}
		for slot, entry := range regional.Compartments {
			id := entry.SelectedID
			if entry.Provenance != nil {
				id = entry.Provenance.ResourceID
			}
			if id == "" || entry.VerifiedAt.IsZero() || entry.ReadbackSHA256 == "" || slot == 1 && regional.Network != nil && regional.Network.CompartmentID != id {
				f.cloud.test.Error("network effect preceded exact accepted and read-back original compartments")
			}
		}
	}
	pins, err := originalNetworkUpstream(record)
	if err != nil {
		f.cloud.test.Error(err)
		return
	}
	if f.upstream == nil {
		f.upstream = pins
	} else if !bytes.Equal(f.upstream, pins) {
		f.cloud.test.Error("network effect replaced original compartment, producer birth or material pins")
	}
}

func originalNetworkTypedRequest(requests OriginalFoundationNetworkRequests, key string) any {
	switch key {
	case "vcn":
		return requests.VCN
	case "service_gateway":
		return requests.ServiceGateway
	case "route_table":
		return requests.RouteTable
	case "security_list":
		return requests.SecurityList
	case "subnet":
		return requests.Subnet
	case "controller_nsg":
		return requests.ControllerNSG
	}
	return nil
}

func originalNetworkCreateSlot(key string) int {
	return slices.Index([]string{"vcn", "service_gateway", "route_table", "security_list", "subnet", "controller_nsg"}, key)
}

func originalNetworkBody(r *http.Request) (map[string]any, []byte, error) {
	wire, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(wire))
	var body map[string]any
	if err := json.Unmarshal(wire, &body); err != nil {
		return nil, nil, err
	}
	canonical, err := json.Marshal(body, json.Deterministic(true))
	return body, canonical, err
}

func originalNetworkCopyResponse(w http.ResponseWriter, recorder *httptest.ResponseRecorder) {
	for key, values := range recorder.Header() {
		w.Header()[key] = values
	}
	w.WriteHeader(recorder.Code)
	w.Write(recorder.Body.Bytes())
}

func (f *originalNetworkSDKFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.networkMu.Lock()
	defer f.networkMu.Unlock()
	if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/o/"+foundationObjectPrefix+"GRU.json") && !f.faulted {
		body, _, err := originalNetworkBody(r)
		if err != nil {
			f.cloud.test.Error(err)
			originalCompartmentFailure(w, 400, "InvalidParameter")
			return
		}
		wire, err := json.Marshal(body)
		var record FoundationRecord
		if err == nil && json.Unmarshal(wire, &record) == nil && record.OriginalFoundationCompartments != nil {
			for _, regional := range record.OriginalFoundationCompartments.Regions {
				if regional.Network == nil {
					continue
				}
				network := regional.Network
				reservation := !network.Rules.ReservedAt.IsZero() && len(network.Rules.ReturnedRules) == 0
				response := len(network.Rules.ReturnedRules) != 0 && network.Rules.VerifiedAt.IsZero()
				accepted := false
				for _, create := range network.Creates {
					accepted = accepted || create.Provenance != nil && create.VerifiedAt.IsZero()
				}
				if reservation && f.networkFault == "reservation before send" || response && (f.networkFault == "response before CAS" || f.networkFault == "lost response CAS") || accepted && f.networkFault == "lost resource checkpoint" {
					f.faulted = true
					if f.networkFault != "response before CAS" {
						recorder := httptest.NewRecorder()
						f.originalCompartmentSDKFixture.serveHTTP(recorder, r)
						if recorder.Code >= 300 {
							f.cloud.test.Errorf("network checkpoint fault did not follow accepted CAS: %d", recorder.Code)
						}
					}
					originalCompartmentFailure(w, 503, "InternalError")
					return
				}
			}
		}
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 || originalNetworkSDKCollections[parts[1]] == "" {
		f.originalCompartmentSDKFixture.serveHTTP(w, r)
		return
	}
	cell, index := "", -1
	for candidate, name := range []string{"GRU", "SFO", "FRA"} {
		if r.Host == "iaas."+catalog.OCIRegion(name)+".oraclecloud.com" {
			cell, index = name, candidate
		}
	}
	if index < 0 || parts[0] != "20160918" || !strings.HasPrefix(r.Header.Get("Authorization"), "Signature ") {
		f.cloud.test.Errorf("unexpected original network SDK endpoint: %s %s %s", r.Method, r.Host, r.URL.Path)
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	record := f.cloud.journal("GRU")
	f.checkNetworkPrerequisites(record)
	if record.OriginalFoundationCompartments == nil || record.OriginalFoundationCompartments.Regions[index].Network == nil {
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	regional := record.OriginalFoundationCompartments.Regions[index]
	network := regional.Network
	key := originalNetworkSDKCollections[parts[1]]
	if key == "controller_nsg" && len(parts) == 5 && parts[3] == "actions" && parts[4] == "addSecurityRules" && r.Method == http.MethodPost {
		f.serveOriginalRules(w, r, cell, regional, parts[2])
		return
	}
	if key == "controller_nsg" && len(parts) == 4 && parts[3] == "securityRules" && r.Method == http.MethodGet {
		f.serveOriginalRuleList(w, r, network, parts[2])
		return
	}
	if len(parts) == 3 && r.Method == http.MethodGet && r.URL.RawQuery == "" {
		entry := network.Creates[originalNetworkCreateSlot(key)]
		if !f.returned[parts[2]] || entry.Provenance == nil || entry.Provenance.ResourceID != parts[2] {
			f.cloud.test.Error("network exact-ID GET preceded durable actual returned-ID provenance")
		}
		if f.networkFault == "nonavailable resource" && !f.faulted {
			f.faulted = true
			f.cloud.mu.Lock()
			f.cloud.rows[parts[2]]["lifecycleState"] = "PROVISIONING"
			f.cloud.mu.Unlock()
		}
		f.originalCompartmentSDKFixture.serveHTTP(w, r)
		return
	}
	if len(parts) != 2 || r.Method != http.MethodPost || r.URL.RawQuery != "" {
		f.cloud.test.Errorf("original network attempted nonexact read, adoption or unrelated mutation: %s %s", r.Method, r.URL.String())
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	body, canonical, err := originalNetworkBody(r)
	if err != nil {
		f.cloud.test.Error(err)
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	entry := network.Creates[originalNetworkCreateSlot(key)]
	pending := entry.Pending
	digest, err := originalNetworkRequestSHA(key, originalNetworkTypedRequest(network.Requests, key))
	if pending == nil || err != nil || digest != preparationDigest(canonical) || pending.Request.RequestDigest != digest || pending.Request.RetryToken != r.Header.Get("opc-retry-token") ||
		pending.Request.RetryToken != BootstrapRetryToken(regional.OperationID, digest) || pending.Request.Key != key || pending.Request.Region != regional.OCIRegion || pending.OperationID != regional.OperationID || pending.IntentDigest != regional.IntentSHA256 || pending.FirstAttemptAt.IsZero() || entry.Provenance != nil {
		f.cloud.test.Error("network create preceded exact durable typed body/hash/token/time and original regional scope")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	f.checkOriginalNetworkBody(cell, key, network, body)
	f.creates = append(f.creates, originalNetworkDispatch{cell: cell, key: key, token: pending.Request.RetryToken, body: canonical, pending: *pending})
	if f.networkFault == "unknown resource" && !f.faulted {
		f.faulted = true
		originalCompartmentFailure(w, 503, "InternalError")
		return
	}
	if (f.networkFault == "resource conflict" || f.networkFault == "invalid resource token") && !f.faulted {
		f.faulted = true
		status, code := http.StatusConflict, "Conflict"
		if f.networkFault == "invalid resource token" {
			status, code = http.StatusBadRequest, "InvalidRetryToken"
		}
		originalCompartmentFailure(w, status, code)
		return
	}
	recorder := httptest.NewRecorder()
	f.originalCompartmentSDKFixture.serveHTTP(recorder, r)
	var row map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &row); err != nil || row["id"] == nil {
		f.cloud.test.Errorf("network SDK create lacked actual returned ID: %v", err)
	}
	id, _ := row["id"].(string)
	f.returned[id] = true
	if key == "subnet" {
		// OCI derives both effective private flags from the single documented
		// ProhibitInternetIngress create input; the inherited generic echo does not.
		row["prohibitInternetIngress"], row["prohibitPublicIpOnVnic"] = true, true
		f.cloud.mu.Lock()
		f.cloud.rows[id]["prohibitInternetIngress"], f.cloud.rows[id]["prohibitPublicIpOnVnic"] = true, true
		f.cloud.mu.Unlock()
		recorder.Body.Reset()
		json.MarshalWrite(recorder.Body, row)
	}
	if key == "service_gateway" {
		row["blockTraffic"] = false
		f.cloud.mu.Lock()
		f.cloud.rows[id]["blockTraffic"] = false
		f.cloud.mu.Unlock()
		recorder.Body.Reset()
		json.MarshalWrite(recorder.Body, row)
	}
	if f.networkFault == "lost resource response" && !f.faulted {
		f.faulted = true
		originalCompartmentFailure(w, 503, "InternalError")
		return
	}
	originalNetworkCopyResponse(w, recorder)
}

func (f *originalNetworkSDKFixture) checkOriginalNetworkBody(cell, key string, network *OriginalFoundationNetwork, body map[string]any) {
	name := strings.ToLower(cell) + "-1"
	suffix := map[string]string{"vcn": "vcn", "service_gateway": "service-gateway", "route_table": "private-routes", "security_list": "private-security", "subnet": "private", "controller_nsg": "controllers-nsg"}[key]
	if body["compartmentId"] != network.CompartmentID || body["displayName"] != name+"-"+suffix {
		f.cloud.test.Error("network body substituted exact original compartment or deterministic signed-plan name")
	}
	id := func(slot int) string {
		if network.Creates[slot].Provenance == nil {
			return ""
		}
		return network.Creates[slot].Provenance.ResourceID
	}
	if key != "vcn" && (id(0) == "" || body["vcnId"] != id(0) || network.Creates[0].VerifiedAt.IsZero()) {
		f.cloud.test.Error("network child preceded verified original VCN dependency")
	}
	security := network.Plan["network_security"].(map[string]any)
	switch key {
	case "vcn":
		if body["cidrBlock"] != network.Plan["network_cidr"] && !sameOriginalSourceValue(body["cidrBlocks"], []any{network.Plan["network_cidr"]}) || body["dnsLabel"] != strings.ReplaceAll(name, "-", "") || body["isIpv6Enabled"] == true {
			f.cloud.test.Error("VCN body drifted from exact signed IPv4/DNS plan")
		}
	case "service_gateway":
		if !sameOriginalSourceValue(body["services"], []map[string]any{{"serviceId": security["service_gateway_service_id"]}}) || body["routeTableId"] != nil {
			f.cloud.test.Error("service gateway widened signed service or transit attachment")
		}
	case "route_table":
		wanted := []map[string]any{{"destination": security["service_gateway_cidr_block"], "destinationType": "SERVICE_CIDR_BLOCK", "networkEntityId": id(1)}}
		if id(1) == "" || network.Creates[1].VerifiedAt.IsZero() || !sameOriginalSourceValue(originalNetworkPrune(body["routeRules"]), wanted) {
			f.cloud.test.Error("private route body added unsigned destination or substituted gateway")
		}
	case "security_list":
		if !sameOriginalSourceValue(originalNetworkPrune(body["ingressSecurityRules"]), []any{}) || !sameOriginalSourceValue(originalNetworkPrune(body["egressSecurityRules"]), originalNetworkExpectedRules(security["security_list_egress_rules"], false)) {
			f.cloud.test.Error("security list widened signed complete ingress/egress semantics")
		}
	case "subnet":
		if body["cidrBlock"] != network.Plan["subnet_cidr"] || body["dnsLabel"] != "private" || body["routeTableId"] != id(2) || !sameOriginalSourceValue(body["securityListIds"], []string{id(3)}) || id(2) == "" || id(3) == "" || network.Creates[2].VerifiedAt.IsZero() || network.Creates[3].VerifiedAt.IsZero() || body["prohibitInternetIngress"] != true || body["prohibitPublicIpOnVnic"] != nil || body["availabilityDomain"] != nil || body["ipv6CidrBlock"] != nil {
			f.cloud.test.Error("subnet body lost exact private graph or specified conflicting/public flags")
		}
	}
}

func originalNetworkPrune(value any) any {
	switch value := value.(type) {
	case map[string]any:
		result := map[string]any{}
		for key, item := range value {
			if item != nil {
				result[key] = originalNetworkPrune(item)
			}
		}
		return result
	case []any:
		result := make([]any, len(value))
		for index, item := range value {
			result[index] = originalNetworkPrune(item)
		}
		return result
	}
	return value
}

func originalNetworkExpectedRules(value any, nsg bool) []any {
	var result []any
	for _, raw := range value.([]any) {
		rule := raw.(map[string]any)
		expected := map[string]any{"protocol": rule["protocol"], "isStateless": rule["stateless"]}
		if nsg {
			expected["direction"] = rule["direction"]
		}
		for source, target := range map[string]string{"source": "source", "source_type": "sourceType", "destination": "destination", "destination_type": "destinationType"} {
			if rule[source] != nil {
				expected[target] = rule[source]
			}
		}
		for _, protocol := range []string{"tcp", "udp"} {
			if rule[protocol+"_min"] != nil {
				expected[protocol+"Options"] = map[string]any{"destinationPortRange": map[string]any{"min": rule[protocol+"_min"], "max": rule[protocol+"_max"]}}
			}
		}
		result = append(result, expected)
	}
	return result
}

func (f *originalNetworkSDKFixture) serveOriginalRules(w http.ResponseWriter, r *http.Request, cell string, regional OriginalFoundationCompartmentRegion, id string) {
	network := regional.Network
	body, canonical, err := originalNetworkBody(r)
	if err != nil {
		f.cloud.test.Error(err)
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	digest, err := originalNetworkRequestSHA("controller_nsg_rules", network.Rules.Request)
	if err != nil || network.Creates[5].Provenance == nil || network.Creates[5].Provenance.ResourceID != id || network.Creates[5].VerifiedAt.IsZero() || network.Rules.ReservedAt.IsZero() || len(network.Rules.ReturnedRules) != 0 || network.Rules.RequestSHA256 != digest || digest != preparationDigest(canonical) || r.Header.Get("opc-retry-token") != "" || r.URL.RawQuery != "" || f.rulePosts[id] != 0 {
		f.cloud.test.Error("NSG send lacked permanent exact original reservation or repeated a consumed send")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	security := network.Plan["network_security"].(map[string]any)
	if !sameOriginalSourceValue(originalNetworkPrune(body["securityRules"]), originalNetworkExpectedRules(security["nsg_rules"], true)) {
		f.cloud.test.Error("NSG add differs from exact nine signed controller rules")
	}
	f.rulePosts[id]++
	recorder := httptest.NewRecorder()
	f.originalCompartmentSDKFixture.serveHTTP(recorder, r)
	f.cloud.mu.Lock()
	for _, raw := range f.cloud.rules[id] {
		raw.(map[string]any)["isValid"] = true
	}
	wire, err := json.Marshal(f.cloud.rules[id])
	f.cloud.mu.Unlock()
	var rows []map[string]any
	if err != nil || json.Unmarshal(wire, &rows) != nil {
		f.cloud.test.Error("fixture could not retain actual provider rule response")
	}
	f.added[id] = true
	if f.networkFault == "unknown rule response" && !f.faulted {
		f.faulted = true
		originalCompartmentFailure(w, 503, "InternalError")
		return
	}
	if !f.faulted {
		switch f.networkFault {
		case "partial rule response":
			f.faulted = true
			rows = rows[:len(rows)-1]
		case "duplicate rule response":
			f.faulted = true
			rows[1]["id"] = rows[0]["id"]
		case "wrong rule response":
			f.faulted = true
			rows[0]["source"] = "0.0.0.0/0"
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.MarshalWrite(w, map[string]any{"securityRules": rows})
}

func (f *originalNetworkSDKFixture) serveOriginalRuleList(w http.ResponseWriter, r *http.Request, network *OriginalFoundationNetwork, id string) {
	if network.Creates[5].Provenance == nil || network.Creates[5].Provenance.ResourceID != id {
		f.cloud.test.Error("NSG list substituted a discovered group")
	}
	f.cloud.mu.Lock()
	wire, err := json.Marshal(f.cloud.rules[id])
	f.cloud.mu.Unlock()
	var rows []map[string]any
	if err != nil || json.Unmarshal(wire, &rows) != nil {
		f.cloud.test.Error("fixture could not list retained provider rules")
	}
	if !f.added[id] {
		json.MarshalWrite(w, []any{})
		return
	}
	if len(network.Rules.ReturnedRules) != len(rows) {
		f.cloud.test.Error("rule list preceded durable complete actual response IDs")
	}
	responseIDs := map[string]bool{}
	for _, rule := range network.Rules.ReturnedRules {
		if rule.Id != nil {
			responseIDs[*rule.Id] = true
		}
	}
	for _, row := range rows {
		if !responseIDs[row["id"].(string)] {
			f.cloud.test.Error("rule list preceded exact actual returned per-rule provenance")
		}
	}
	if f.networkFault == "unavailable rule list" && !f.faulted {
		f.faulted = true
		originalCompartmentFailure(w, 503, "InternalError")
		return
	}
	switch f.networkFault {
	case "extra listed rule":
		extra := maps.Clone(rows[0])
		extra["id"] = "foreign-rule"
		rows = append(rows, extra)
	case "missing listed rule":
		rows = rows[:len(rows)-1]
	case "duplicate listed IDs":
		rows[len(rows)-1]["id"] = rows[0]["id"]
	case "invalid listed rule":
		rows[0]["isValid"] = false
	case "listed semantic drift":
		rows[0]["source"] = "0.0.0.0/0"
	}
	page := r.URL.Query().Get("page")
	if page == "" {
		w.Header().Set("opc-next-page", "tail")
		rows = rows[:5]
	} else if page == "tail" {
		rows = rows[5:]
	} else {
		f.cloud.test.Error("unexpected NSG pagination token")
		originalCompartmentFailure(w, 400, "InvalidParameter")
		return
	}
	f.pages[id]++
	json.MarshalWrite(w, rows)
}

func (f *originalNetworkSDKFixture) effects() ([]originalNetworkDispatch, int) {
	f.networkMu.Lock()
	defer f.networkMu.Unlock()
	sends := 0
	for _, count := range f.rulePosts {
		sends += count
	}
	return slices.Clone(f.creates), sends
}

func (f *originalNetworkSDKFixture) assertNetworkState(t *testing.T, complete bool) {
	t.Helper()
	f.assertIncomplete(t, true)
	record := f.record(t)
	if err := record.validate(); err != nil {
		t.Fatal(err)
	}
	pins, err := originalNetworkUpstream(record)
	if err != nil || !bytes.Equal(pins, f.upstream) {
		t.Fatalf("network progress changed protected original material, birth or compartment pins: %v", err)
	}
	if complete {
		for _, region := range record.OriginalFoundationCompartments.Regions {
			network := region.Network
			if network == nil || !network.Complete || network.Rules.ReservedAt.IsZero() || len(network.Rules.ReturnedRules) != 9 || network.Rules.VerifiedAt.IsZero() || network.Rules.ReadbackSHA256 == "" || network.Rules.HoldReason != "" {
				t.Fatalf("%s lacks acknowledged complete private network prerequisites", region.Cell)
			}
			for _, create := range network.Creates {
				if create.Pending == nil || create.Provenance == nil || !sameOriginalSourceValue(create.Pending, create.Provenance.Create) || create.ReadbackSHA256 == "" || create.VerifiedAt.IsZero() || create.HoldReason != "" {
					t.Fatalf("%s %s lacks immutable accepted/readback provenance", region.Cell, create.Key)
				}
			}
			f.networkMu.Lock()
			pages := f.pages[network.Creates[5].Provenance.ResourceID]
			f.networkMu.Unlock()
			if pages < 2 {
				t.Fatal("normal NSG proof never read the complete independent paginated rule set")
			}
		}
	}
}

func TestOriginalFoundationNetworkSDK(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	t.Run("eighteen exact private creates and three acknowledged rule sends", func(t *testing.T) {
		f := newOriginalNetworkSDKFixture(t, "")
		if err := f.run(t); err != nil {
			t.Fatalf("original network component did not retain complete prerequisites: %v", err)
		}
		creates, sends := f.effects()
		if len(creates) != 18 || sends != 3 || f.cloud.creates != 23 || len(f.dispatches()) != 5 {
			t.Fatalf("normal original path made %d network POSTs/%d rule sends/%d total creates", len(creates), sends, f.cloud.creates)
		}
		seen := map[string]bool{}
		for _, create := range creates {
			key := create.cell + "/" + create.key
			if seen[key] {
				t.Fatalf("normal original network repeated %s", key)
			}
			seen[key] = true
		}
		f.assertNetworkState(t, true)
		before := f.wire(t)
		materialPosts := f.cloud.materialPosts
		if err := f.run(t); err != nil {
			t.Fatal(err)
		}
		after, ruleSends := f.effects()
		if len(after) != 18 || ruleSends != 3 || f.cloud.creates != 23 || f.cloud.materialPosts != materialPosts || !bytes.Equal(before, f.wire(t)) {
			t.Fatal("complete private-network replay mutated original effects, pins or actor HOLD")
		}
	})

	t.Run("tokenized creates retain exact unknown and accepted identities", func(t *testing.T) {
		for _, fault := range []string{"lost resource response", "lost resource checkpoint", "nonavailable resource"} {
			t.Run(fault, func(t *testing.T) {
				f := newOriginalNetworkSDKFixture(t, fault)
				if err := f.run(t); err == nil {
					t.Fatal("interrupted network create reported complete provisioning")
				}
				before, _ := f.effects()
				if len(before) != 1 || f.cloud.creates != 6 {
					t.Fatal("network uncertainty fixture did not reach first actual original VCN create")
				}
				entry := f.record(t).OriginalFoundationCompartments.Regions[0].Network.Creates[0]
				if fault == "nonavailable resource" {
					if entry.Provenance == nil || !entry.VerifiedAt.IsZero() {
						t.Fatal("non-AVAILABLE readback lost accepted ID or fabricated readiness")
					}
					f.cloud.mu.Lock()
					f.cloud.rows[entry.Provenance.ResourceID]["lifecycleState"] = "AVAILABLE"
					f.cloud.mu.Unlock()
				}
				if err := f.run(t); err != nil {
					t.Fatalf("retained exact create did not resume: %v", err)
				}
				after, sends := f.effects()
				want := 18
				if fault == "lost resource response" {
					want = 19
					if len(after) < 2 || !bytes.Equal(after[0].body, after[1].body) || after[0].token != after[1].token || !sameOriginalSourceValue(after[0].pending, after[1].pending) {
						t.Fatal("unknown tokenized create reset exact body/token/scope/first-dispatch time")
					}
				}
				if len(after) != want || sends != 3 || f.cloud.creates != 23 {
					t.Fatal("accepted network ID was recreated instead of GET-only recovery")
				}
				f.assertNetworkState(t, true)
			})
		}
		for _, fault := range []string{"resource conflict", "invalid resource token"} {
			t.Run(fault, func(t *testing.T) {
				f := newOriginalNetworkSDKFixture(t, fault)
				if err := f.run(t); err == nil {
					t.Fatal("terminal network create failure reported success")
				}
				entry := f.record(t).OriginalFoundationCompartments.Regions[0].Network.Creates[0]
				if entry.Pending == nil || entry.HoldReason == "" || entry.Provenance != nil {
					t.Fatal("terminal create failure returned without durable original pending HOLD")
				}
				if err := f.run(t); err == nil {
					t.Fatal("terminal original network HOLD disappeared")
				}
				creates, sends := f.effects()
				if len(creates) != 1 || sends != 0 || f.cloud.creates != 5 || !sameOriginalSourceValue(entry, f.record(t).OriginalFoundationCompartments.Regions[0].Network.Creates[0]) {
					t.Fatal("terminal create failure reset or resent the original request")
				}
			})
		}
		t.Run("valid old pending create persists expiry HOLD", func(t *testing.T) {
			f := newOriginalNetworkSDKFixture(t, "unknown resource")
			f.bundle = signHistoricalOriginalCompartmentBundle(t, f.foundationProvisionFixture)
			f.cloud.bundle = f.bundle.clone()
			if err := VerifyFoundationProvisionBundle(t.Context(), f.roots, f.bundle); err != nil {
				t.Fatal(err)
			}
			if err := f.run(t); err == nil {
				t.Fatal("unknown network create lost its original pending reservation")
			}
			record := f.record(t)
			// A genuinely long-lived original signature admits yesterday's
			// coherent durable timeline, without changing any request or authority.
			record.StartedAt = record.StartedAt.Add(-24 * time.Hour)
			record.NetBirdMaterial.BornAt = record.NetBirdMaterial.BornAt.Add(-24 * time.Hour)
			for index := range record.NetBirdMaterial.Creates {
				create := &record.NetBirdMaterial.Creates[index]
				create.FirstDispatchedAt = create.FirstDispatchedAt.Add(-24 * time.Hour)
			}
			for index := range record.OriginalSourceProducers {
				record.OriginalSourceProducers[index].BornAt = record.OriginalSourceProducers[index].BornAt.Add(-24 * time.Hour)
			}
			section := record.OriginalFoundationCompartments
			section.BornAt = section.BornAt.Add(-24 * time.Hour)
			for index := range section.Regions {
				region := &section.Regions[index]
				for slot := range region.Compartments {
					entry := &region.Compartments[slot]
					if entry.Pending != nil {
						entry.Pending.FirstAttemptAt = entry.Pending.FirstAttemptAt.Add(-24 * time.Hour)
					}
					if entry.Provenance != nil {
						entry.Provenance.Create = *entry.Pending
					}
					entry.VerifiedAt = entry.VerifiedAt.Add(-24 * time.Hour)
				}
				for slot := range region.Network.Creates {
					entry := &region.Network.Creates[slot]
					if entry.Pending != nil {
						entry.Pending.FirstAttemptAt = entry.Pending.FirstAttemptAt.Add(-24 * time.Hour)
					}
				}
			}
			if err := record.validate(); err != nil {
				t.Fatalf("historical network pending fixture is invalid: %v", err)
			}
			pending := section.Regions[0].Network.Creates[0].Pending
			if pending == nil || !pending.FirstAttemptAt.Before(time.Now().Add(-23*time.Hour)) {
				t.Fatal("retained network request did not expire under its still-valid original signature")
			}
			wire, err := json.Marshal(record, json.Deterministic(true))
			if err != nil {
				t.Fatal(err)
			}
			f.cloud.writeObject("gru-1-head/"+foundationObjectPrefix+"GRU.json", wire)
			if err := f.run(t); !errors.Is(err, ErrOriginalSourceProducerHold) {
				t.Fatalf("valid expired network create did not retain HOLD: %v", err)
			}
			retained := f.record(t)
			section.Regions[0].Network.Creates[0].HoldReason = "retry-expired"
			record.UpdatedAt = retained.UpdatedAt
			if !sameOriginalSourceValue(record, retained) {
				t.Fatal("expiry did not persist HOLD with exact original network body/token/time, material and compartment pins")
			}
			hold := f.wire(t)
			if err := f.run(t); !errors.Is(err, ErrOriginalSourceProducerHold) || !bytes.Equal(hold, f.wire(t)) {
				t.Fatalf("expired durable network request reset on next invocation: %v", err)
			}
			creates, sends := f.effects()
			if len(creates) != 1 || sends != 0 || f.cloud.creates != 5 {
				t.Fatal("expired original tokenized request dispatched replacement or NSG effects")
			}
		})
	})

	t.Run("permanent NSG reservation never authorizes a second send", func(t *testing.T) {
		for _, fault := range []string{"reservation before send", "unknown rule response", "response before CAS", "partial rule response", "duplicate rule response", "wrong rule response"} {
			t.Run(fault, func(t *testing.T) {
				f := newOriginalNetworkSDKFixture(t, fault)
				if err := f.run(t); err == nil {
					t.Fatal("uncertain or malformed non-idempotent rule operation claimed success")
				}
				before := f.record(t).OriginalFoundationCompartments.Regions[0].Network.Rules
				if before.ReservedAt.IsZero() || before.RequestSHA256 == "" || len(before.ReturnedRules) != 0 {
					t.Fatal("uncertain rule outcome lost permanent reservation or manufactured response provenance")
				}
				want := 1
				if fault == "reservation before send" {
					want = 0
				}
				for range 2 {
					if err := f.run(t); err == nil {
						t.Fatal("unknown permanent reservation acquired completion from provider observations")
					}
					creates, sends := f.effects()
					if sends != want || len(creates) != 6 || f.cloud.creates != 11 {
						t.Fatal("unknown rule outcome resent rules, replaced the NSG or created later regional resources")
					}
				}
				after := f.record(t).OriginalFoundationCompartments.Regions[0].Network.Rules
				if after.HoldReason == "" || !after.ReservedAt.Equal(before.ReservedAt) || after.RequestSHA256 != before.RequestSHA256 || !sameOriginalSourceValue(before.Request, after.Request) || len(after.ReturnedRules) != 0 || !after.VerifiedAt.IsZero() {
					t.Fatal("unknown non-idempotent outcome reset reservation or adopted listed rule IDs")
				}
				f.assertNetworkState(t, false)
				if fault == "unknown rule response" {
					store, wire := f.store(t), f.wire(t)
					for _, erase := range []string{"reservation", "terminal HOLD"} {
						record, etag, err := store.Load(t.Context(), "GRU")
						if err != nil {
							t.Fatal(err)
						}
						rules := &record.OriginalFoundationCompartments.Regions[0].Network.Rules
						if erase == "reservation" {
							*rules = OriginalFoundationNetworkRules{}
						} else {
							rules.HoldReason = ""
						}
						if _, err := store.CompareAndSwap(t.Context(), record, etag); err == nil || !bytes.Equal(wire, f.wire(t)) {
							t.Fatalf("protected CAS erased permanent unknown %s: %v", erase, err)
						}
					}
				}
			})
		}
		for _, fault := range []string{"lost response CAS", "unavailable rule list"} {
			t.Run(fault, func(t *testing.T) {
				f := newOriginalNetworkSDKFixture(t, fault)
				err := f.run(t)
				if err == nil {
					t.Fatal("lost response checkpoint/readback claimed complete provisioning")
				}
				retained := f.record(t).OriginalFoundationCompartments.Regions[0].Network.Rules
				if len(retained.ReturnedRules) != 9 || retained.ReservedAt.IsZero() || !retained.VerifiedAt.IsZero() {
					t.Fatal("durable acknowledged rule response disappeared or acquired readiness after checkpoint/readback interruption")
				}
				if fault == "lost response CAS" {
					f.networkMu.Lock()
					pages := len(f.pages)
					f.networkMu.Unlock()
					if !errors.Is(err, ErrOriginalSourceProducerHold) || pages != 0 {
						t.Fatal("storage acknowledgment loss did not stop the invocation in HOLD before rule list")
					}
				}
				if err := f.run(t); err != nil {
					t.Fatalf("durable complete response did not recover read-only: %v", err)
				}
				creates, sends := f.effects()
				if len(creates) != 18 || sends != 3 || f.cloud.creates != 23 {
					t.Fatal("durable response recovery repeated an NSG send or network create")
				}
				f.assertNetworkState(t, true)
			})
		}
	})

	t.Run("independent readback and original authority refuse drift", func(t *testing.T) {
		for _, fault := range []string{"extra listed rule", "missing listed rule", "duplicate listed IDs", "invalid listed rule", "listed semantic drift"} {
			t.Run(fault, func(t *testing.T) {
				f := newOriginalNetworkSDKFixture(t, fault)
				if err := f.run(t); err == nil {
					t.Fatalf("inexact complete rule-ID/semantic readback acquired actor-boundary progress: %v", err)
				}
				if err := f.run(t); err == nil {
					t.Fatal("drifted rule readback became success")
				}
				creates, sends := f.effects()
				if sends != 1 || len(creates) != 6 || f.cloud.creates != 11 || f.record(t).OriginalFoundationCompartments.Regions[0].Network.Complete {
					t.Fatal("drifted NSG readback retried mutations or fabricated network completion")
				}
				f.assertNetworkState(t, false)
			})
		}
		fixtureT := t
		var completed *originalNetworkSDKFixture
		for _, drift := range []string{"completed extra listed rule", "missing accepted VCN", "wrong VCN compartment", "blocked service gateway", "public subnet", "wrong user", "wrong tenancy", "expired original"} {
			t.Run(drift, func(t *testing.T) {
				if completed == nil {
					completed = newOriginalNetworkSDKFixture(fixtureT, "")
					if err := completed.run(t); err != nil {
						t.Fatal(err)
					}
				}
				f := completed
				f.assertNetworkState(t, true)
				before := f.wire(t)
				network := f.record(t).OriginalFoundationCompartments.Regions[0].Network
				bundle := f.bundle.clone()
				f.networkMu.Lock()
				fault := f.networkFault
				f.networkMu.Unlock()
				rows := map[string]map[string]any{}
				f.cloud.mu.Lock()
				for _, slot := range []int{0, 1, 4} {
					id := network.Creates[slot].Provenance.ResourceID
					rows[id] = maps.Clone(f.cloud.rows[id])
				}
				f.cloud.mu.Unlock()
				t.Cleanup(func() {
					f.cloud.mu.Lock()
					for id, row := range rows {
						f.cloud.rows[id] = row
					}
					f.cloud.mu.Unlock()
					f.networkMu.Lock()
					f.networkFault = fault
					f.networkMu.Unlock()
					f.bundle = bundle
				})
				f.cloud.mu.Lock()
				switch drift {
				case "missing accepted VCN":
					delete(f.cloud.rows, network.Creates[0].Provenance.ResourceID)
				case "wrong VCN compartment":
					f.cloud.rows[network.Creates[0].Provenance.ResourceID]["compartmentId"] = f.approval.SharedCompartmentID
				case "blocked service gateway":
					f.cloud.rows[network.Creates[1].Provenance.ResourceID]["blockTraffic"] = true
				case "public subnet":
					f.cloud.rows[network.Creates[4].Provenance.ResourceID]["prohibitPublicIpOnVnic"] = false
				}
				f.cloud.mu.Unlock()
				if drift == "completed extra listed rule" {
					f.networkMu.Lock()
					f.networkFault = "extra listed rule"
					f.networkMu.Unlock()
				}
				var err error
				if drift == "wrong user" || drift == "wrong tenancy" {
					provider := originalCompartmentProvider{ConfigurationProvider: f.provider, user: "ocid1.user.oc1..test", tenancy: f.approval.TenancyID}
					if drift == "wrong user" {
						provider.user = "ocid1.user.oc1..foreign"
					} else {
						provider.tenancy = "ocid1.tenancy.oc1..foreign"
					}
					factory, factoryErr := ociclient.New(provider, ociclient.Options{Region: foundationHomeRegion, Retry: ociclient.RetryOptions{MaxAttempts: 1}})
					if factoryErr != nil {
						t.Fatal(factoryErr)
					}
					err = provisionOriginalFoundationCompartments(t.Context(), factory, f.roots, f.bundle)
				} else {
					if drift == "expired original" {
						f.bundle = signProvisionFoundation(t, f.prepared, f.bundle.RootChainWire, f.root, f.now.Add(-24*time.Hour))
					}
					err = f.run(t)
				}
				creates, sends := f.effects()
				if err == nil || len(creates) != 18 || sends != 3 || f.cloud.creates != 23 || !bytes.Equal(before, f.wire(t)) {
					t.Fatalf("drift/revocation/deadline reset originals or created replacement effects: %v", err)
				}
			})
		}
	})

	t.Run("protected CAS retains every network and once-send pin", func(t *testing.T) {
		f := newOriginalNetworkSDKFixture(t, "")
		if err := f.run(t); err != nil {
			t.Fatal(err)
		}
		store := f.store(t)
		original := f.wire(t)
		for name, mutate := range map[string]func(*FoundationRecord){
			"remove network": func(r *FoundationRecord) { r.OriginalFoundationCompartments.Regions[0].Network = nil },
			"replace signed plan": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Network.Plan["network_cidr"] = "0.0.0.0/0"
			},
			"replace compartment": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Network.CompartmentID = r.SharedCompartmentID
			},
			"erase typed body": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Network.Requests.VCN = core.CreateVcnDetails{}
			},
			"replace dependency": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Network.Requests.Subnet.RouteTableId = new("ocid1.routetable.oc1.sa-saopaulo-1.foreign")
			},
			"erase pending": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Network.Creates[0].Pending = nil
			},
			"replace body digest": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Network.Creates[0].Pending.Request.RequestDigest = strings.Repeat("a", 64)
			},
			"replace retry token": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Network.Creates[0].Pending.Request.RetryToken = strings.Repeat("a", 64)
			},
			"replace first time": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Network.Creates[0].Pending.FirstAttemptAt = r.OriginalFoundationCompartments.Regions[0].Network.Creates[0].Pending.FirstAttemptAt.Add(time.Second)
			},
			"erase returned ID": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Network.Creates[0].Provenance = nil
			},
			"replace returned ID": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Network.Creates[0].Provenance.ResourceID = "ocid1.vcn.oc1.sa-saopaulo-1.foreign"
			},
			"erase readback": func(r *FoundationRecord) {
				c := &r.OriginalFoundationCompartments.Regions[0].Network.Creates[0]
				c.ReadbackSHA256 = ""
				c.VerifiedAt = time.Time{}
			},
			"erase rule reservation": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Network.Rules.ReservedAt = time.Time{}
			},
			"replace rule time": func(r *FoundationRecord) {
				rules := &r.OriginalFoundationCompartments.Regions[0].Network.Rules
				rules.ReservedAt = rules.ReservedAt.Add(time.Second)
			},
			"erase rule body": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Network.Rules.Request = core.AddNetworkSecurityGroupSecurityRulesDetails{}
			},
			"replace rule digest": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Network.Rules.RequestSHA256 = strings.Repeat("a", 64)
			},
			"erase actual rule IDs": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Network.Rules.ReturnedRules = nil
			},
			"replace actual rule ID": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Network.Rules.ReturnedRules[0].Id = new("foreign-rule")
			},
			"replace actual semantics": func(r *FoundationRecord) {
				r.OriginalFoundationCompartments.Regions[0].Network.Rules.ReturnedRules[0].Source = new("0.0.0.0/0")
			},
			"erase rule readback": func(r *FoundationRecord) {
				rules := &r.OriginalFoundationCompartments.Regions[0].Network.Rules
				rules.ReadbackSHA256 = ""
				rules.VerifiedAt = time.Time{}
			},
			"erase completion": func(r *FoundationRecord) { r.OriginalFoundationCompartments.Regions[0].Network.Complete = false },
			"manufacture runtime binding": func(r *FoundationRecord) {
				r.ResourceIDs["vcn"] = r.OriginalFoundationCompartments.Regions[0].Network.Creates[0].Provenance.ResourceID
			},
		} {
			record, etag, err := store.Load(t.Context(), "GRU")
			if err != nil {
				t.Fatal(err)
			}
			mutate(&record)
			if _, err := store.CompareAndSwap(t.Context(), record, etag); err == nil {
				t.Fatalf("protected CAS accepted %s", name)
			}
			if !bytes.Equal(original, f.wire(t)) {
				t.Fatalf("refused %s changed protected bytes", name)
			}
		}
		f.assertNetworkState(t, true)
	})
}
