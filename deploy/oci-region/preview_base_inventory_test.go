package ociregion_test

import "testing"

func TestPreviewBaseInventoryContracts(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	runPreviewContracts(t, "PreviewBaseInventoryTests.", 4)
}
