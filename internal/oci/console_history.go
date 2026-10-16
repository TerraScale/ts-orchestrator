package oci

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/core"
)

const (
	consoleHistoryAction          = "console-history-capture"
	maxConsoleHistoryBytes        = 1 << 20
	maxConsoleHistoryRetryAge     = 23 * time.Hour
	defaultConsoleHistoryTimeout  = 2 * time.Minute
	defaultConsoleHistoryPollWait = time.Second
)

var (
	ErrConsoleHistoryAttemptMismatch = errors.New("OCI console-history attempt timestamp differs from its durable intent")
	ErrConsoleHistoryRecoveryHold    = errors.New("OCI console-history capture requires operator reconciliation")
	ErrConsoleHistoryTerminal        = errors.New("OCI console-history capture reached a terminal failure")
	ErrConsoleHistoryIncomplete      = errors.New("OCI console-history content is absent or incomplete")
)

// ConsoleHistoryCaptureRequest binds an OCI capture to one expected instance
// and a stable retry token. OriginalAttemptAt is an optional assertion against
// the first timestamp stored in the durable OCI journal. Leave it zero to use
// the journal's timestamp without carrying a second clock value in callers.
type ConsoleHistoryCaptureRequest struct {
	InstanceID        string
	RetryToken        string
	OriginalAttemptAt time.Time
}

// ConsoleHistory is scope-checked metadata for one exact OCI console-history
// resource. It never contains console output.
type ConsoleHistory struct {
	ID                 string
	InstanceID         string
	CompartmentID      string
	AvailabilityDomain string
	State              string
	TimeCreated        time.Time
	RequestID          string
	ETag               string
}

// ConsoleHistoryEvidence keeps bounded console output in memory only. Callers
// should persist a verified digest before asking the provider to delete History.
type ConsoleHistoryEvidence struct {
	History ConsoleHistory
	Content []byte
}

// ConsoleHistoryAPI is the narrow OCI Compute SDK seam used by the provider.
// Tests inject a fake; production uses the official region-pinned v65 client.
type ConsoleHistoryAPI interface {
	GetInstance(context.Context, core.GetInstanceRequest) (core.GetInstanceResponse, error)
	CaptureConsoleHistory(context.Context, core.CaptureConsoleHistoryRequest) (core.CaptureConsoleHistoryResponse, error)
	GetConsoleHistory(context.Context, core.GetConsoleHistoryRequest) (core.GetConsoleHistoryResponse, error)
	GetConsoleHistoryContent(context.Context, core.GetConsoleHistoryContentRequest) (core.GetConsoleHistoryContentResponse, error)
	DeleteConsoleHistory(context.Context, core.DeleteConsoleHistoryRequest) (core.DeleteConsoleHistoryResponse, error)
}

// ConsoleHistoryProvider is pinned to one validated OCI region and refuses
// capture unless the expected instance has exact configured scope and durable
// controller ownership.
type ConsoleHistoryProvider struct {
	config         RegionConfig
	journal        Journal
	api            ConsoleHistoryAPI
	captureTimeout time.Duration
	pollInterval   time.Duration
}

// NewConsoleHistoryProvider validates the region binding and constructs an
// injectable provider around the official OCI Compute API seam.
func NewConsoleHistoryProvider(config RegionConfig, intent RegionIntent, journal Journal, api ConsoleHistoryAPI) (*ConsoleHistoryProvider, error) {
	if err := config.Validate(intent); err != nil {
		return nil, err
	}
	if journal == nil || api == nil {
		return nil, errors.New("OCI console-history provider requires a durable journal and Compute API client")
	}
	return &ConsoleHistoryProvider{
		config: config, journal: journal, api: api,
		captureTimeout: defaultConsoleHistoryTimeout, pollInterval: defaultConsoleHistoryPollWait,
	}, nil
}

// NewInstancePrincipalConsoleHistoryProvider creates the official Compute
// client using instance-principal authentication and pins it to the validated
// region endpoint.
func NewInstancePrincipalConsoleHistoryProvider(config RegionConfig, intent RegionIntent, journal Journal) (*ConsoleHistoryProvider, error) {
	if err := config.Validate(intent); err != nil {
		return nil, err
	}
	region, err := config.Region.OCIRegion()
	if err != nil {
		return nil, err
	}
	factory, err := ociclient.InstancePrincipal(region)
	if err != nil {
		return nil, err
	}
	client, err := factory.Compute()
	if err != nil {
		return nil, err
	}
	ociclient.PinHost(&client.BaseClient, config.Endpoint)
	// Console-history calls share the fleet's Compute API metrics.
	client.HTTPClient = ociclient.Instrument(client.HTTPClient, "compute")
	return NewConsoleHistoryProvider(config, intent, journal, client)
}

// Capture starts or recovers the one OCI console-history operation identified
// by request. Its result ID is durable before it is returned.
func (provider *ConsoleHistoryProvider) Capture(ctx context.Context, request ConsoleHistoryCaptureRequest) (ConsoleHistory, error) {
	if err := provider.validateRequest(request); err != nil {
		return ConsoleHistory{}, err
	}
	captureCtx, cancel := provider.operationContext(ctx)
	defer cancel()

	intent, result, found, err := provider.beginCapture(captureCtx, request)
	if err != nil {
		return ConsoleHistory{}, err
	}
	if found && !result.Unknown {
		if result.ResourceID == "" {
			return ConsoleHistory{}, errors.New("durable OCI console-history result has no history ID")
		}
		return provider.Get(captureCtx, request, result.ResourceID)
	}
	if err := checkConsoleHistoryRetryWindow(intent, time.Now().UTC()); err != nil {
		return ConsoleHistory{}, err
	}
	if _, err := provider.ownedInstance(captureCtx, request.InstanceID); err != nil {
		return ConsoleHistory{}, err
	}
	if err := captureCtx.Err(); err != nil {
		return ConsoleHistory{}, err
	}

	captured, err := provider.api.CaptureConsoleHistory(captureCtx, core.CaptureConsoleHistoryRequest{
		CaptureConsoleHistoryDetails: core.CaptureConsoleHistoryDetails{InstanceId: new(request.InstanceID)},
		OpcRetryToken:                new(request.RetryToken),
	})
	if err != nil {
		unknown := provider.recordUnknown(captureCtx, intent, err)
		return ConsoleHistory{}, unknown
	}
	history, err := normalizeConsoleHistory(captured.ConsoleHistory, stringValue(captured.OpcRequestId), stringValue(captured.Etag))
	if err != nil {
		return ConsoleHistory{}, provider.recordUnknown(captureCtx, intent, err)
	}
	if err := provider.validateHistory(history, request.InstanceID, ""); err != nil {
		return ConsoleHistory{}, provider.recordUnknown(captureCtx, intent, err)
	}
	if err := provider.journal.RecordResult(captureCtx, OperationResult{
		Intent: intent, ResourceID: history.ID, ETag: history.ETag,
	}); err != nil {
		unknown := provider.recordUnknown(captureCtx, intent, err)
		return ConsoleHistory{}, unknown
	}
	return history, nil
}

// CaptureEvidence captures, polls to SUCCEEDED, and returns at most one MiB
// of output in memory. Successful history remains until Delete is called.
func (provider *ConsoleHistoryProvider) CaptureEvidence(ctx context.Context, request ConsoleHistoryCaptureRequest) (ConsoleHistoryEvidence, error) {
	if err := provider.validateRequest(request); err != nil {
		return ConsoleHistoryEvidence{}, err
	}
	captureCtx, cancel := provider.operationContext(ctx)
	defer cancel()
	history, err := provider.Capture(captureCtx, request)
	if err != nil {
		return ConsoleHistoryEvidence{}, err
	}
	return provider.readCapturedEvidence(captureCtx, request.InstanceID, history.ID)
}

// Get returns metadata only for the exact history ID durably recorded under
// request's stable retry token and expected instance.
func (provider *ConsoleHistoryProvider) Get(ctx context.Context, request ConsoleHistoryCaptureRequest, historyID string) (ConsoleHistory, error) {
	if err := provider.validateRequest(request); err != nil {
		return ConsoleHistory{}, err
	}
	operationCtx, cancel := provider.operationContext(ctx)
	defer cancel()
	if historyID == "" {
		return ConsoleHistory{}, errors.New("OCI console-history ID is required")
	}
	if _, err := provider.confirmedCapture(operationCtx, request, historyID); err != nil {
		return ConsoleHistory{}, err
	}
	response, err := provider.api.GetConsoleHistory(operationCtx, core.GetConsoleHistoryRequest{
		InstanceConsoleHistoryId: new(historyID),
	})
	if err != nil {
		return ConsoleHistory{}, fmt.Errorf("get OCI console-history metadata: %w", err)
	}
	history, err := normalizeConsoleHistory(response.ConsoleHistory, stringValue(response.OpcRequestId), stringValue(response.Etag))
	if err != nil {
		return ConsoleHistory{}, err
	}
	if err := provider.validateHistory(history, request.InstanceID, historyID); err != nil {
		return ConsoleHistory{}, err
	}
	return history, nil
}

// ReadContent retrieves bounded output only after the exact history is
// durably bound to request and has reached SUCCEEDED.
func (provider *ConsoleHistoryProvider) ReadContent(ctx context.Context, request ConsoleHistoryCaptureRequest, historyID string) ([]byte, error) {
	if err := provider.validateRequest(request); err != nil {
		return nil, err
	}
	operationCtx, cancel := provider.operationContext(ctx)
	defer cancel()
	history, err := provider.Get(operationCtx, request, historyID)
	if err != nil {
		return nil, err
	}
	if history.State != string(core.ConsoleHistoryLifecycleStateSucceeded) {
		return nil, consoleHistoryStateError(history.State)
	}
	return provider.readContent(operationCtx, historyID)
}

// Delete removes only the exact confirmed history ID after re-reading and
// validating its immutable instance, compartment, and availability-domain
// binding. It is intended for use after the caller durably stores its digest.
func (provider *ConsoleHistoryProvider) Delete(ctx context.Context, request ConsoleHistoryCaptureRequest, historyID string) error {
	if err := provider.validateRequest(request); err != nil {
		return err
	}
	operationCtx, cancel := provider.operationContext(ctx)
	defer cancel()
	history, err := provider.Get(operationCtx, request, historyID)
	if err != nil {
		return err
	}
	if history.ETag == "" {
		return errors.New("OCI console-history metadata has no ETag for conditional deletion")
	}
	if _, err := provider.api.DeleteConsoleHistory(operationCtx, core.DeleteConsoleHistoryRequest{
		InstanceConsoleHistoryId: new(history.ID),
		IfMatch:                  new(history.ETag),
	}); err != nil {
		return fmt.Errorf("delete OCI console-history %s: %w", history.ID, err)
	}
	return nil
}

func (provider *ConsoleHistoryProvider) beginCapture(ctx context.Context, request ConsoleHistoryCaptureRequest) (OperationIntent, OperationResult, bool, error) {
	createdAt := request.OriginalAttemptAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	} else {
		createdAt = createdAt.UTC()
	}
	intent := OperationIntent{
		Action: consoleHistoryAction, Key: request.RetryToken,
		Region: provider.config.Region, Generation: provider.config.Generation,
		Owner: provider.config.Owner, ResourceID: request.InstanceID,
		CreatedAt: createdAt,
	}
	if err := provider.journal.RecordIntent(ctx, intent); err != nil {
		return OperationIntent{}, OperationResult{}, false, fmt.Errorf("persist OCI console-history intent: %w", err)
	}
	result, found, err := provider.journal.GetResult(ctx, intent)
	if err != nil {
		return OperationIntent{}, OperationResult{}, false, fmt.Errorf("read OCI console-history intent: %w", err)
	}
	if result.Intent.CreatedAt.IsZero() || !sameIntent(result.Intent, intent) {
		return OperationIntent{}, OperationResult{}, false, errors.New("OCI journal returned a different console-history intent")
	}
	if !request.OriginalAttemptAt.IsZero() && !result.Intent.CreatedAt.Equal(request.OriginalAttemptAt) {
		return OperationIntent{}, OperationResult{}, false, ErrConsoleHistoryAttemptMismatch
	}
	return result.Intent, result, found, nil
}

func (provider *ConsoleHistoryProvider) confirmedCapture(ctx context.Context, request ConsoleHistoryCaptureRequest, historyID string) (OperationIntent, error) {
	createdAt := request.OriginalAttemptAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	} else {
		createdAt = createdAt.UTC()
	}
	intent := OperationIntent{
		Action: consoleHistoryAction, Key: request.RetryToken,
		Region: provider.config.Region, Generation: provider.config.Generation,
		Owner: provider.config.Owner, ResourceID: request.InstanceID, CreatedAt: createdAt,
	}
	result, found, err := provider.journal.GetResult(ctx, intent)
	if err != nil {
		return OperationIntent{}, fmt.Errorf("read durable OCI console-history result: %w", err)
	}
	if !found || result.Unknown || result.ResourceID == "" || result.ResourceID != historyID ||
		result.Intent.CreatedAt.IsZero() || !sameIntent(result.Intent, intent) {
		return OperationIntent{}, errors.New("OCI console-history ID is not the confirmed result for this request")
	}
	if !request.OriginalAttemptAt.IsZero() && !result.Intent.CreatedAt.Equal(request.OriginalAttemptAt) {
		return OperationIntent{}, ErrConsoleHistoryAttemptMismatch
	}
	return result.Intent, nil
}

func (provider *ConsoleHistoryProvider) readCapturedEvidence(ctx context.Context, instanceID, historyID string) (ConsoleHistoryEvidence, error) {
	history, err := provider.pollHistory(ctx, instanceID, historyID)
	if err != nil {
		return ConsoleHistoryEvidence{}, err
	}
	content, err := provider.readContent(ctx, historyID)
	if err != nil {
		if errors.Is(err, ErrConsoleHistoryIncomplete) {
			cleanupErr := provider.deleteExact(ctx, history)
			if cleanupErr != nil {
				return ConsoleHistoryEvidence{}, errors.Join(err, cleanupErr)
			}
		}
		return ConsoleHistoryEvidence{}, err
	}
	return ConsoleHistoryEvidence{History: history, Content: content}, nil
}

func (provider *ConsoleHistoryProvider) pollHistory(ctx context.Context, instanceID, historyID string) (ConsoleHistory, error) {
	for {
		response, err := provider.api.GetConsoleHistory(ctx, core.GetConsoleHistoryRequest{
			InstanceConsoleHistoryId: new(historyID),
		})
		if err != nil {
			return ConsoleHistory{}, fmt.Errorf("poll OCI console-history metadata: %w", err)
		}
		history, err := normalizeConsoleHistory(response.ConsoleHistory, stringValue(response.OpcRequestId), stringValue(response.Etag))
		if err != nil {
			return ConsoleHistory{}, err
		}
		if err := provider.validateHistory(history, instanceID, historyID); err != nil {
			return ConsoleHistory{}, err
		}
		switch history.State {
		case string(core.ConsoleHistoryLifecycleStateSucceeded):
			return history, nil
		case string(core.ConsoleHistoryLifecycleStateFailed):
			failure := fmt.Errorf("%w: OCI reported state %s", ErrConsoleHistoryTerminal, history.State)
			if cleanupErr := provider.deleteExact(ctx, history); cleanupErr != nil {
				return ConsoleHistory{}, errors.Join(failure, cleanupErr)
			}
			return ConsoleHistory{}, failure
		case string(core.ConsoleHistoryLifecycleStateRequested), string(core.ConsoleHistoryLifecycleStateGettingHistory):
			if err := waitConsoleHistoryPoll(ctx, provider.pollInterval); err != nil {
				return ConsoleHistory{}, err
			}
		default:
			return ConsoleHistory{}, fmt.Errorf("OCI console-history has unsupported lifecycle state %q", history.State)
		}
	}
}

func (provider *ConsoleHistoryProvider) readContent(ctx context.Context, historyID string) ([]byte, error) {
	response, err := provider.api.GetConsoleHistoryContent(ctx, core.GetConsoleHistoryContentRequest{
		InstanceConsoleHistoryId: new(historyID),
		Offset:                   new(0),
		Length:                   new(maxConsoleHistoryBytes),
	})
	if err != nil {
		return nil, fmt.Errorf("read OCI console-history content: %w", err)
	}
	if response.Value == nil || len(*response.Value) == 0 || len(*response.Value) > maxConsoleHistoryBytes ||
		response.OpcBytesRemaining == nil || *response.OpcBytesRemaining != 0 {
		return nil, ErrConsoleHistoryIncomplete
	}
	return []byte(*response.Value), nil
}

func (provider *ConsoleHistoryProvider) deleteExact(ctx context.Context, history ConsoleHistory) error {
	if history.ID == "" || history.ETag == "" {
		return errors.New("verified OCI console-history cleanup requires an exact ID and ETag")
	}
	if err := provider.validateHistory(history, history.InstanceID, history.ID); err != nil {
		return err
	}
	if _, err := provider.api.DeleteConsoleHistory(ctx, core.DeleteConsoleHistoryRequest{
		InstanceConsoleHistoryId: new(history.ID), IfMatch: new(history.ETag),
	}); err != nil {
		return fmt.Errorf("delete failed OCI console-history %s: %w", history.ID, err)
	}
	return nil
}

func (provider *ConsoleHistoryProvider) recordUnknown(ctx context.Context, intent OperationIntent, cause error) error {
	journalErr := provider.journal.RecordResult(ctx, OperationResult{Intent: intent, Unknown: true})
	return &ConsoleHistoryOutcomeUnknownError{Cause: cause, JournalErr: journalErr}
}

func (provider *ConsoleHistoryProvider) ownedInstance(ctx context.Context, instanceID string) (ResourceIdentity, error) {
	response, err := provider.api.GetInstance(ctx, core.GetInstanceRequest{InstanceId: new(instanceID)})
	if err != nil {
		return ResourceIdentity{}, fmt.Errorf("get OCI console-history target instance: %w", err)
	}
	instance := response.Instance
	cloud := cloudInstance(instance, stringValue(response.Etag))
	ociRegion, err := provider.config.Region.OCIRegion()
	if err != nil {
		return ResourceIdentity{}, err
	}
	tags := cloud.FreeformTags
	createKey := tags[tagCreateKey]
	identity := ResourceIdentity{
		ID: cloud.ID, Region: provider.config.Region, Generation: provider.config.Generation,
		Owner: provider.config.Owner, CreateKey: createKey,
	}
	if cloud.ID != instanceID || cloud.CompartmentID != provider.config.CompartmentID ||
		cloud.AvailabilityDomain != provider.config.AvailabilityDomain || instance.Region == nil || *instance.Region != ociRegion ||
		cloud.ETag == "" || !slices.Contains(provider.config.FaultDomains, cloud.FaultDomain) || cloud.LifecycleState != "RUNNING" ||
		tags[tagManagedBy] != managedByValue || tags[tagOwner] != provider.config.Owner ||
		tags[tagRegion] != string(provider.config.Region) || tags[tagGeneration] != fmt.Sprint(provider.config.Generation) ||
		tags[tagResource] != resourceMemberHost || !validCreateKey(createKey) || tags[tagHostNode] != hostNode(provider.config, createKey) {
		return ResourceIdentity{}, fmt.Errorf("%w: console-history target instance %s has missing or mismatched scope", ErrForeignResource, instanceID)
	}
	owned, err := provider.journal.IsOwnedInstance(ctx, identity)
	if err != nil {
		return ResourceIdentity{}, fmt.Errorf("read OCI console-history target ownership: %w", err)
	}
	if !owned {
		return ResourceIdentity{}, fmt.Errorf("%w: console-history target instance %s has no durable controller ownership", ErrForeignResource, instanceID)
	}
	return identity, nil
}

func (provider *ConsoleHistoryProvider) validateHistory(history ConsoleHistory, instanceID, historyID string) error {
	if history.ID == "" || history.ID != historyID && historyID != "" || history.InstanceID != instanceID ||
		history.CompartmentID != provider.config.CompartmentID || history.AvailabilityDomain != provider.config.AvailabilityDomain ||
		history.TimeCreated.IsZero() || !validConsoleHistoryState(history.State) {
		return fmt.Errorf("%w: OCI console-history metadata is outside its exact configured scope", ErrForeignResource)
	}
	return nil
}

func (provider *ConsoleHistoryProvider) validateRequest(request ConsoleHistoryCaptureRequest) error {
	if provider == nil || provider.api == nil || provider.journal == nil {
		return errors.New("OCI console-history provider is not initialized")
	}
	if !isOCID(request.InstanceID, "instance") || !validConsoleHistoryRetryToken(request.RetryToken) {
		return errors.New("OCI console-history request requires an instance OCID and a stable retry token of at most 64 visible ASCII bytes")
	}
	return nil
}

func (provider *ConsoleHistoryProvider) operationContext(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := provider.captureTimeout
	if timeout <= 0 {
		timeout = defaultConsoleHistoryTimeout
	}
	return context.WithTimeout(ctx, timeout)
}

func normalizeConsoleHistory(value core.ConsoleHistory, requestID, etag string) (ConsoleHistory, error) {
	if value.Id == nil || value.InstanceId == nil || value.CompartmentId == nil || value.AvailabilityDomain == nil || value.TimeCreated == nil {
		return ConsoleHistory{}, errors.New("OCI console-history metadata is missing required fields")
	}
	return ConsoleHistory{
		ID: *value.Id, InstanceID: *value.InstanceId, CompartmentID: *value.CompartmentId,
		AvailabilityDomain: *value.AvailabilityDomain, State: string(value.LifecycleState),
		TimeCreated: value.TimeCreated.Time.UTC(), RequestID: requestID, ETag: etag,
	}, nil
}

func checkConsoleHistoryRetryWindow(intent OperationIntent, now time.Time) error {
	if intent.CreatedAt.IsZero() || now.Before(intent.CreatedAt) || now.Sub(intent.CreatedAt) >= maxConsoleHistoryRetryAge {
		return &ConsoleHistoryRecoveryHoldError{
			InstanceID: intent.ResourceID, RetryToken: intent.Key,
			Reason: "the immutable OCI capture intent is outside the 23-hour automatic retry window",
		}
	}
	return nil
}

func consoleHistoryStateError(state string) error {
	if state == string(core.ConsoleHistoryLifecycleStateFailed) {
		return fmt.Errorf("%w: OCI reported state %s", ErrConsoleHistoryTerminal, state)
	}
	return fmt.Errorf("OCI console-history is not ready; current state is %q", state)
}

func validConsoleHistoryState(state string) bool {
	switch state {
	case string(core.ConsoleHistoryLifecycleStateRequested), string(core.ConsoleHistoryLifecycleStateGettingHistory),
		string(core.ConsoleHistoryLifecycleStateSucceeded), string(core.ConsoleHistoryLifecycleStateFailed):
		return true
	default:
		return false
	}
}

func validConsoleHistoryRetryToken(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if char < 0x21 || char > 0x7e {
			return false
		}
	}
	return true
}

func waitConsoleHistoryPoll(ctx context.Context, interval time.Duration) error {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// ConsoleHistoryOutcomeUnknownError means the OCI capture may have succeeded,
// but no durable history ID is available. A retry is safe only with its same
// stable retry token and within the original journal window.
type ConsoleHistoryOutcomeUnknownError struct {
	Cause      error
	JournalErr error
}

func (err *ConsoleHistoryOutcomeUnknownError) Error() string {
	if err.JournalErr != nil {
		return fmt.Sprintf("%v: OCI console-history capture outcome is unknown; durable result update also failed: %v", ErrOutcomeUnknown, err.JournalErr)
	}
	return fmt.Sprintf("%v: OCI console-history capture outcome is unknown: %v", ErrOutcomeUnknown, err.Cause)
}

func (err *ConsoleHistoryOutcomeUnknownError) Unwrap() []error {
	causes := []error{ErrOutcomeUnknown}
	if err.Cause != nil {
		causes = append(causes, err.Cause)
	}
	if err.JournalErr != nil {
		causes = append(causes, err.JournalErr)
	}
	return causes
}

// ConsoleHistoryRecoveryHoldError prevents expired retry tokens from creating
// a second capture after OCI's idempotency window may have elapsed.
type ConsoleHistoryRecoveryHoldError struct {
	InstanceID string
	RetryToken string
	Reason     string
}

func (err *ConsoleHistoryRecoveryHoldError) Error() string {
	return fmt.Sprintf("OCI console-history capture for %s is held: %s", err.InstanceID, err.Reason)
}

func (err *ConsoleHistoryRecoveryHoldError) Unwrap() error { return ErrConsoleHistoryRecoveryHold }
