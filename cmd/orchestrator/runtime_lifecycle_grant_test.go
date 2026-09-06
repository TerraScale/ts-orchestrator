package main

import "testing"

func TestRestoreRequestDigestVector(t *testing.T) {
	got := restoreRequestDigest("source-owner", "source-database", "recovery-point", "recovery-digest", "target-owner", "target-database", "journal-cut", 7, 1)
	if got != "8de75d48c6ed3bba6d0b05f266c390a3fb36c155ba423a225e8e733fae64413d" {
		t.Fatalf("digest = %s", got)
	}
}
