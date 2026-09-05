package guestdiagnostic

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStartupJournalLimitsAndCategories(t *testing.T) {
	var tls Service
	ParseJournal(&tls, []byte(`{"MESSAGE":"Error: ProductionStartup(Transport(\"a TLS material file is unsafe or invalid\")) SECRET","PRIORITY":"3"}`))
	if len(tls.Categories) != 1 || tls.Categories[0] != "tls-material-rejected" {
		t.Fatalf("TLS category lost: %+v", tls)
	}
	var initial Service
	ParseJournal(&initial, []byte(`{"MESSAGE":"not a directory SECRET","PRIORITY":"3"}`))
	if len(initial.Categories) != 1 || initial.Categories[0] != "path-not-directory" {
		t.Fatalf("path category lost: %+v", initial)
	}
	var engine Service
	ParseJournal(&engine, []byte(`{"MESSAGE":"Error: MissingConfigurationPath","PRIORITY":"3"}`))
	if len(engine.Categories) != 1 || engine.Categories[0] != "terrabase-configuration-missing" {
		t.Fatalf("engine category lost: %+v", engine)
	}
	var composition Service
	ParseJournal(&composition, []byte(`{"MESSAGE":"orchestrator: production runtime requires configured estate publisher, key rotation, free-tier reaper, restore drill, and delivery mirror adapters","PRIORITY":"3"}`))
	if len(composition.Categories) != 1 || composition.Categories[0] != "production-composition-missing" {
		t.Fatalf("composition category lost: %+v", composition)
	}
	var estate Service
	ParseJournal(&estate, []byte(`{"MESSAGE":"orchestrator: OCI estate verification requires TS_ORCH_OCI_ESTATE_FILE, TS_ORCH_OCI_KEY_ID, and TS_ORCH_OCI_PRIVATE_KEY_FILE","PRIORITY":"3"}`))
	if len(estate.Categories) != 1 || estate.Categories[0] != "oci-estate-configuration-missing" {
		t.Fatalf("estate category lost: %+v", estate)
	}
	var report Service
	ParseJournal(&report, []byte(strings.Repeat(`{"MESSAGE":"permission denied TOKEN","PRIORITY":"3"}`+"\n", 100)))
	if report.JournalEntries != 20 || report.SeverityCounts[3] != 20 || len(report.Categories) != 1 {
		t.Fatalf("unbounded journal: %+v", report)
	}
}

func TestStartupReportJSONAndCategoryOrder(t *testing.T) {
	report := Service{Unit: "terrascale-orchestrator.service", Observation: "observed"}
	ParseStatus(&report, []byte("MainPID=123\nActiveState=failed\nSubState=SECRET_STATUS\nResult=exit-code\nExecMainCode=1\nExecMainStatus=2\nUnexpected=SECRET_FIELD\n"))
	// Input order differs from the fixed category order; raw text never survives.
	ParseJournal(&report, []byte(`{"MESSAGE":"CONNECTION REFUSED SECRET permission denied initial control: initialgrant: not a directory no such file or directory","PRIORITY":"3"}`))
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	const expected = `{"unit":"terrascale-orchestrator.service","observation":"observed","mainPid":123,"activeState":"failed","subState":"unknown","result":"exit-code","execMainCode":1,"execMainStatus":2,"journalEntries":1,"severityCounts":[0,0,0,1,0,0,0,0],"categories":["file-missing","path-not-directory","initial-admission-rejected","initial-control-rejected","permission-denied","connection-refused"]}`
	if string(raw) != expected {
		t.Fatalf("diagnostic wire changed:\n%s", raw)
	}
	var unavailable Service
	ParseJournal(&unavailable, []byte("malformed SECRET\n"+`{"MESSAGE":"SECRET","PRIORITY":"9"}`))
	raw, err = json.Marshal(unavailable)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"unit":"","observation":"","journalEntries":1,"journalUnavailable":true,"severityCounts":[0,0,0,0,0,0,0,0]}` {
		t.Fatalf("unavailable report changed: %s", raw)
	}
}
