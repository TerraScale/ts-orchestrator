package oci

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func TestConsoleHistoryCaptureEvidenceAndExactDelete(t *testing.T) {
	config, regionIntent, journal, api, provider, request := newConsoleHistoryTest(t)
	api.content = "serial transcript"
	api.historyStates = []string{string(core.ConsoleHistoryLifecycleStateGettingHistory), string(core.ConsoleHistoryLifecycleStateSucceeded)}

	evidence, err := provider.CaptureEvidence(t.Context(), request)
	if err != nil {
		t.Fatalf("CaptureEvidence: %v", err)
	}
	if string(evidence.Content) != api.content || evidence.History.ID != api.historyID || evidence.History.InstanceID != request.InstanceID {
		t.Fatalf("unexpected capture evidence: history=%+v content=%q", evidence.History, evidence.Content)
	}
	if api.captureCalls != 1 || len(api.retryTokens) != 1 || api.retryTokens[0] != request.RetryToken {
		t.Fatalf("capture did not use the exact stable retry token: calls=%d tokens=%v", api.captureCalls, api.retryTokens)
	}
	if api.contentLength != maxConsoleHistoryBytes || api.contentOffset != 0 {
		t.Fatalf("content request was not bounded: offset=%d length=%d", api.contentOffset, api.contentLength)
	}

	journalIntent := OperationIntent{
		Action: consoleHistoryAction, Key: request.RetryToken, Region: config.Region,
		Generation: config.Generation, Owner: config.Owner, ResourceID: request.InstanceID,
		CreatedAt: request.OriginalAttemptAt,
	}
	result, found, err := journal.GetResult(t.Context(), journalIntent)
	if err != nil || !found || result.ResourceID != evidence.History.ID || !result.Intent.CreatedAt.Equal(request.OriginalAttemptAt) {
		t.Fatalf("console capture was not durably bound: result=%+v found=%v err=%v", result, found, err)
	}
	entry, err := journal.kv.Get(t.Context(), operationKey(result.Intent))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(entry.Value()), api.content) {
		t.Fatal("raw console output was persisted in the OCI journal")
	}

	if err := provider.Delete(t.Context(), request, evidence.History.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if len(api.deletedIDs) != 1 || api.deletedIDs[0] != evidence.History.ID || api.deletedETags[0] != api.historyETag {
		t.Fatalf("delete did not target the exact verified history with its ETag: IDs=%v ETags=%v", api.deletedIDs, api.deletedETags)
	}
	if config.Region != RegionGRU || regionIntent.Generation != config.Generation {
		t.Fatal("test setup did not bind the provider to its validated region")
	}
}

func newConsoleHistoryTest(t *testing.T) (RegionConfig, RegionIntent, *KVJournal, *fakeConsoleHistoryAPI, *ConsoleHistoryProvider, ConsoleHistoryCaptureRequest) {
	t.Helper()
	config, intent := testRegionConfig()
	journal, err := NewKVJournal(testJournalBucket(t))
	if err != nil {
		t.Fatal(err)
	}
	instanceID := "ocid1.instance.oc1..aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	createKey := "00000000000000000000000001"
	launch := testLaunchIntent(createKey)
	if err := journal.RecordIntent(t.Context(), launch); err != nil {
		t.Fatal(err)
	}
	if err := journal.RecordResult(t.Context(), OperationResult{Intent: launch, ResourceID: instanceID}); err != nil {
		t.Fatal(err)
	}
	api := &fakeConsoleHistoryAPI{
		instance: core.Instance{
			Id: new(instanceID), CompartmentId: new(config.CompartmentID),
			AvailabilityDomain: new(config.AvailabilityDomain), FaultDomain: new("FAULT-DOMAIN-1"),
			Region: new("sa-saopaulo-1"), LifecycleState: core.InstanceLifecycleStateRunning,
			FreeformTags: hostTags(config, createKey),
		},
		instanceETag: "instance-etag", instanceID: instanceID, config: config,
		historyID:   "ocid1.instanceconsolehistory.oc1..bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		historyETag: "history-etag", historyStates: []string{string(core.ConsoleHistoryLifecycleStateSucceeded)},
	}
	provider, err := NewConsoleHistoryProvider(config, intent, journal, api)
	if err != nil {
		t.Fatal(err)
	}
	return config, intent, journal, api, provider, ConsoleHistoryCaptureRequest{
		InstanceID: instanceID, RetryToken: "capture-console-01", OriginalAttemptAt: time.Now().UTC(),
	}
}

type fakeConsoleHistoryAPI struct {
	instance          core.Instance
	instanceETag      string
	instanceID        string
	historyInstanceID string
	config            RegionConfig
	historyID         string
	historyETag       string
	historyStates     []string
	historyStateAt    int
	content           string
	bytesRemaining    int
	captureErr        error
	captureCalls      int
	getHistoryCalls   int
	contentCalls      int
	contentLength     int
	contentOffset     int
	retryTokens       []string
	deletedIDs        []string
	deletedETags      []string
}

func (api *fakeConsoleHistoryAPI) GetInstance(_ context.Context, request core.GetInstanceRequest) (core.GetInstanceResponse, error) {
	if request.InstanceId == nil || *request.InstanceId != api.instanceID {
		return core.GetInstanceResponse{}, fmt.Errorf("unexpected instance request")
	}
	return core.GetInstanceResponse{Instance: api.instance, Etag: new(api.instanceETag)}, nil
}

func (api *fakeConsoleHistoryAPI) CaptureConsoleHistory(_ context.Context, request core.CaptureConsoleHistoryRequest) (core.CaptureConsoleHistoryResponse, error) {
	api.captureCalls++
	api.retryTokens = append(api.retryTokens, stringValue(request.OpcRetryToken))
	if api.captureErr != nil {
		return core.CaptureConsoleHistoryResponse{}, api.captureErr
	}
	if request.CaptureConsoleHistoryDetails.InstanceId == nil || *request.CaptureConsoleHistoryDetails.InstanceId != api.instanceID {
		return core.CaptureConsoleHistoryResponse{}, fmt.Errorf("unexpected capture instance")
	}
	return core.CaptureConsoleHistoryResponse{
		ConsoleHistory: api.history(string(core.ConsoleHistoryLifecycleStateRequested)),
		Etag:           new(api.historyETag), OpcRequestId: new("capture-request-id"),
	}, nil
}

func (api *fakeConsoleHistoryAPI) GetConsoleHistory(_ context.Context, request core.GetConsoleHistoryRequest) (core.GetConsoleHistoryResponse, error) {
	api.getHistoryCalls++
	if request.InstanceConsoleHistoryId == nil || *request.InstanceConsoleHistoryId != api.historyID {
		return core.GetConsoleHistoryResponse{}, fmt.Errorf("unexpected history ID")
	}
	state := string(core.ConsoleHistoryLifecycleStateSucceeded)
	if api.historyStateAt < len(api.historyStates) {
		state = api.historyStates[api.historyStateAt]
		api.historyStateAt++
	} else if len(api.historyStates) != 0 {
		lastState := api.historyStates[len(api.historyStates)-1]
		if lastState == string(core.ConsoleHistoryLifecycleStateRequested) || lastState == string(core.ConsoleHistoryLifecycleStateGettingHistory) {
			state = lastState
		}
	}
	return core.GetConsoleHistoryResponse{
		ConsoleHistory: api.history(state), Etag: new(api.historyETag), OpcRequestId: new("get-request-id"),
	}, nil
}

func (api *fakeConsoleHistoryAPI) GetConsoleHistoryContent(_ context.Context, request core.GetConsoleHistoryContentRequest) (core.GetConsoleHistoryContentResponse, error) {
	api.contentCalls++
	if request.InstanceConsoleHistoryId == nil || *request.InstanceConsoleHistoryId != api.historyID {
		return core.GetConsoleHistoryContentResponse{}, fmt.Errorf("unexpected history content ID")
	}
	if request.Offset != nil {
		api.contentOffset = *request.Offset
	}
	if request.Length != nil {
		api.contentLength = *request.Length
	}
	return core.GetConsoleHistoryContentResponse{
		Value: new(api.content), OpcBytesRemaining: new(api.bytesRemaining),
	}, nil
}

func (api *fakeConsoleHistoryAPI) DeleteConsoleHistory(_ context.Context, request core.DeleteConsoleHistoryRequest) (core.DeleteConsoleHistoryResponse, error) {
	api.deletedIDs = append(api.deletedIDs, stringValue(request.InstanceConsoleHistoryId))
	api.deletedETags = append(api.deletedETags, stringValue(request.IfMatch))
	return core.DeleteConsoleHistoryResponse{}, nil
}

func (api *fakeConsoleHistoryAPI) history(state string) core.ConsoleHistory {
	instanceID := api.historyInstanceID
	if instanceID == "" {
		instanceID = api.instanceID
	}
	return core.ConsoleHistory{
		Id: new(api.historyID), InstanceId: new(instanceID), CompartmentId: new(api.config.CompartmentID),
		AvailabilityDomain: new(api.config.AvailabilityDomain), LifecycleState: core.ConsoleHistoryLifecycleStateEnum(state),
		TimeCreated: &common.SDKTime{Time: time.Now().UTC()},
	}
}
