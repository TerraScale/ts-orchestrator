package natscell

// JetStream metadata subjects the narrowly scoped membership user may call.
// They are system-account APIs; the claim-update system user cannot use them.
const (
	MembershipServerRemoveSubject = "$JS.API.SERVER.REMOVE"
	MembershipMetaStepdownSubject = "$JS.API.META.LEADER.STEPDOWN"
)
