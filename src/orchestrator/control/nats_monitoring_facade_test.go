package control

import (
	"reflect"
	"testing"
)

func TestNatsMonitoringPermissionPlanCompatibilityFacade(t *testing.T) {
	plan, err := NewNatsMonitoringPermissionPlan(
		[]string{NatsMonitoringSubjectsJetStream, NatsMonitoringSubjectsConnections},
		[]string{"_INBOX.>", NatsMonitoringSubjectsJetStreamAdvisories},
	)
	if err != nil {
		t.Fatalf("construct permission plan through control facade: %v", err)
	}

	if want := []string{NatsMonitoringSubjectsConnections, NatsMonitoringSubjectsJetStream}; !reflect.DeepEqual(plan.Publish, want) {
		t.Fatalf("publish subjects = %#v, want %#v", plan.Publish, want)
	}
	if want := []string{NatsMonitoringSubjectsJetStreamAdvisories, "_INBOX.>"}; !reflect.DeepEqual(plan.Subscribe, want) {
		t.Fatalf("subscribe subjects = %#v, want %#v", plan.Subscribe, want)
	}

	if _, err := NewNatsMonitoringPermissionPlan([]string{"$SYS.unauthorized"}, nil); err == nil {
		t.Fatal("facade accepted an unauthorized publish subject")
	}
}
