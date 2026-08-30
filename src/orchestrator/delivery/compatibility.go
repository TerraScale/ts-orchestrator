package delivery

// These aliases keep the migration surface discoverable for callers that used
// the C# vocabulary while retaining Go's concise method-oriented API.
type ForgejoWebhookEnvelope = WebhookEnvelope
type ForgejoWebhookVerification = WebhookVerification
type ForgejoWebhookKind = WebhookKind
type ForgejoWebhookError = WebhookError

const (
	ForgejoWebhookUnspecified = WebhookUnspecified
	ForgejoWebhookPush        = WebhookPush
	ForgejoWebhookPullRequest = WebhookPullRequest
)

type ForgejoSourceConfiguration = SourceConfig
type ForgejoSourceClient = SourceClient
type ForgejoResolvedRevision = ResolvedRevision
type ForgejoBranchObservation = BranchObservation
type ForgejoSourceFile = SourceFile
type ForgejoSourceArchive = SourceArchive
type ForgejoWebhookJournalReceipt = JournalReceipt
type ForgejoWebhookJournalDisposition = JournalDisposition
type ForgejoSourceJournalDisposition = SourceJournalDisposition
type ForgejoSourceJournalReceipt = SourceJournalReceipt
type ForgejoCiTriggerPlan = TriggerPlan
type ForgejoCiTriggerDisposition = TriggerDisposition
type ForgejoCiTriggerReason = TriggerReason

func ForgejoWebhookVerify(payload, secret []byte, expectedRepository, contentType, signature, deliveryID, event string) WebhookVerification {
	return VerifyWebhook(payload, secret, expectedRepository, contentType, signature, deliveryID, event)
}
func ForgejoCiTriggerPlanFor(e *WebhookEnvelope) *TriggerPlan { return PlanTrigger(e) }
