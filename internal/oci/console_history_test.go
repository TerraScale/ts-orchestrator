package oci

import (
	"context"
	"errors"
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

func TestConsoleHistoryRefusesForeignInstanceBeforeCapture(t *testing.T) {
	_, _, _, api, provider, request := newConsoleHistoryTest(t)
	api.instance.CompartmentId = new("ocid1.compartment.oc1..foreign")

	_, err := provider.Capture(t.Context(), request)
	if !errors.Is(err, ErrForeignResource) {
		t.Fatalf("foreign instance scope was not refused: %v", err)
	}
	if api.captureCalls != 0 {
		t.Fatalf("foreign instance reached CaptureConsoleHistory %d times", api.captureCalls)
	}
}

func TestConsoleHistoryMarksMismatchedCaptureAsUnknownWithoutCleanup(t *testing.T) {
	_, _, _, api, provider, request := newConsoleHistoryTest(t)
	api.historyInstanceID = "ocid1.instance.oc1..cccccccccccccccccccccccccccccccccccccccccccccccccccc"

	_, err := provider.Capture(t.Context(), request)
	if !errors.Is(err, ErrForeignResource) || !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("mismatched returned history was not rejected as an unknown outcome: %v", err)
	}
	if api.captureCalls != 1 || len(api.deletedIDs) != 0 {
		t.Fatalf("mismatched history was adopted or guessed for cleanup: captures=%d deletes=%v", api.captureCalls, api.deletedIDs)
	}
}

func TestConsoleHistoryExpiredUnknownIntentCannotRetryWithFreshTimestamp(t *testing.T) {
	config, _, journal, api, provider, request := newConsoleHistoryTest(t)
	oldAttempt := time.Now().Add(-24 * time.Hour).UTC()
	request.OriginalAttemptAt = oldAttempt
	intent := OperationIntent{
		Action: consoleHistoryAction, Key: request.RetryToken, Region: config.Region,
		Generation: config.Generation, Owner: config.Owner, ResourceID: request.InstanceID,
		CreatedAt: oldAttempt,
	}
	if err := journal.RecordIntent(t.Context(), intent); err != nil {
		t.Fatal(err)
	}
	if err := journal.RecordResult(t.Context(), OperationResult{Intent: intent, Unknown: true}); err != nil {
		t.Fatal(err)
	}

	_, err := provider.Capture(t.Context(), request)
	if !errors.Is(err, ErrConsoleHistoryRecoveryHold) {
		t.Fatalf("expired unknown capture was not held: %v", err)
	}
	if _, ok := errors.AsType[*ConsoleHistoryRecoveryHoldError](err); !ok {
		t.Fatalf("expired retry did not return typed recovery hold: %T %v", err, err)
	}
	if api.captureCalls != 0 {
		t.Fatalf("expired retry reached OCI capture %d times", api.captureCalls)
	}

	request.OriginalAttemptAt = time.Now().UTC()
	_, err = provider.Capture(t.Context(), request)
	if !errors.Is(err, ErrConsoleHistoryAttemptMismatch) || api.captureCalls != 0 {
		t.Fatalf("caller timestamp refreshed an expired intent: calls=%d err=%v", api.captureCalls, err)
	}
	stored, found, err := journal.GetResult(t.Context(), intent)
	if err != nil || !found || !stored.Unknown || !stored.Intent.CreatedAt.Equal(oldAttempt) {
		t.Fatalf("retry changed the immutable attempt timestamp: found=%v result=%+v err=%v", found, stored, err)
	}
}

func TestConsoleHistoryAmbiguousRetryUsesOnlySameTokenAndTimestamp(t *testing.T) {
	_, _, journal, api, provider, request := newConsoleHistoryTest(t)
	api.captureErr = errors.New("response lost after request")

	_, err := provider.Capture(t.Context(), request)
	if !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("ambiguous capture did not return typed unknown outcome: %v", err)
	}
	if _, ok := errors.AsType[*ConsoleHistoryOutcomeUnknownError](err); !ok {
		t.Fatalf("ambiguous capture returned no typed error: %T", err)
	}

	api.captureErr = nil
	_, err = provider.Capture(t.Context(), request)
	if err != nil {
		t.Fatalf("retry with original token and timestamp: %v", err)
	}
	if api.captureCalls != 2 || api.retryTokens[0] != request.RetryToken || api.retryTokens[1] != request.RetryToken {
		t.Fatalf("ambiguous retry did not reuse its stable token: calls=%d tokens=%v", api.captureCalls, api.retryTokens)
	}

	freshTimestamp := request
	freshTimestamp.OriginalAttemptAt = time.Now().UTC()
	_, err = provider.Capture(t.Context(), freshTimestamp)
	if !errors.Is(err, ErrConsoleHistoryAttemptMismatch) || api.captureCalls != 2 {
		t.Fatalf("fresh caller timestamp reset a retry window: calls=%d err=%v", api.captureCalls, err)
	}
	intent := OperationIntent{
		Action: consoleHistoryAction, Key: request.RetryToken, Region: RegionGRU,
		Generation: 7, Owner: "orchestrator", ResourceID: request.InstanceID,
		CreatedAt: request.OriginalAttemptAt,
	}
	result, found, err := journal.GetResult(t.Context(), intent)
	if err != nil || !found || result.Unknown || !result.Intent.CreatedAt.Equal(request.OriginalAttemptAt) {
		t.Fatalf("stable-token retry changed durable capture result: found=%v result=%+v err=%v", found, result, err)
	}
}

func TestConsoleHistoryTerminalFailureDeletesOnlyExactHistory(t *testing.T) {
	_, _, _, api, provider, request := newConsoleHistoryTest(t)
	api.historyStates = []string{string(core.ConsoleHistoryLifecycleStateFailed)}

	_, err := provider.CaptureEvidence(t.Context(), request)
	if !errors.Is(err, ErrConsoleHistoryTerminal) {
		t.Fatalf("FAILED history did not stop evidence retrieval: %v", err)
	}
	if api.contentCalls != 0 || len(api.deletedIDs) != 1 || api.deletedIDs[0] != api.historyID {
		t.Fatalf("failed history was not safely cleaned up: reads=%d deletes=%v", api.contentCalls, api.deletedIDs)
	}
}

func TestConsoleHistoryRejectsOversizeAndTruncatedContent(t *testing.T) {
	tests := []struct {
		name      string
		content   string
		remaining int
	}{
		{name: "oversize", content: strings.Repeat("x", maxConsoleHistoryBytes+1)},
		{name: "truncated", content: "partial transcript", remaining: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, _, api, provider, request := newConsoleHistoryTest(t)
			api.historyStates = []string{string(core.ConsoleHistoryLifecycleStateSucceeded)}
			api.content = test.content
			api.bytesRemaining = test.remaining

			_, err := provider.CaptureEvidence(t.Context(), request)
			if !errors.Is(err, ErrConsoleHistoryIncomplete) {
				t.Fatalf("incomplete content was accepted: %v", err)
			}
			if len(api.deletedIDs) != 1 || api.deletedIDs[0] != api.historyID {
				t.Fatalf("incomplete history was not cleaned up by exact ID: %v", api.deletedIDs)
			}
		})
	}
}

func TestConsoleHistoryPollingHonorsCallerDeadline(t *testing.T) {
	_, _, journal, api, provider, request := newConsoleHistoryTest(t)
	provider.pollInterval = time.Millisecond
	api.historyStates = []string{string(core.ConsoleHistoryLifecycleStateRequested)}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Millisecond)
	defer cancel()

	_, err := provider.CaptureEvidence(ctx, request)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("capture polling ignored caller deadline: %v", err)
	}
	if api.captureCalls != 1 || api.getHistoryCalls < 2 || len(api.deletedIDs) != 0 {
		t.Fatalf("bounded poll had unexpected effects: captures=%d gets=%d deletes=%v", api.captureCalls, api.getHistoryCalls, api.deletedIDs)
	}
	intent := OperationIntent{
		Action: consoleHistoryAction, Key: request.RetryToken, Region: RegionGRU,
		Generation: 7, Owner: "orchestrator", ResourceID: request.InstanceID,
		CreatedAt: request.OriginalAttemptAt,
	}
	result, found, err := journal.GetResult(t.Context(), intent)
	if err != nil || !found || result.ResourceID != api.historyID {
		t.Fatalf("timed-out poll lost its durable known history ID: found=%v result=%+v err=%v", found, result, err)
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
	createKey := "node-console-proof"
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
