package control

import "terrascale.tech/orchestrator/src/orchestrator/journal"

// NatsOperationJournalStore remains available from control while ownership of
// the store and its closed JetStream validation lives in journal.
var NatsOperationJournalStore = journal.NatsOperationJournalStore
