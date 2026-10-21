//go:build fixturetest

package bootstrapmaterial

// The root-call qualification lives in bootstrapmaterial_test because rootoci imports this package.
var (
	TestConfig        = testConfig
	LoadJournal       = loadJournal
	CheckpointJournal = checkpointJournal
	Digest            = digest
	MetadataName      = metadataName
	JournalName       = journalName
	JournalTempName   = journalTempName
)
