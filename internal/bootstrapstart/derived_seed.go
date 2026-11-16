package bootstrapstart

import (
	"context"
)

// DerivedSeedJournal loads an existing completion when proposed is nil. A
// proposal must be durably checkpointed before returning the winning bytes.
type DerivedSeedJournal func(context.Context, *ExternalSeedCompletionRecords) (ExternalSeedCompletionRecords, error)
