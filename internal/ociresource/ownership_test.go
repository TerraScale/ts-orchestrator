package ociresource

import "testing"

func TestPersistentControllerRefusesMissingForeignAndPartialOwnership(t *testing.T) {
	ownership := Ownership{Owner: "cell-gru"}
	key := widgetKey("a")
	cases := map[string]Tags{
		"empty":        {},
		"unrelated":    {Freeform: map[string]string{"CostCenter": "infra"}},
		"other-owner":  (Ownership{Owner: "other"}).Stamp(key, 1, "d"),
		"defined-only": {Defined: map[string]map[string]any{"terrascale": {"managed-by": managedByValue, "owner": "cell-gru", "resource-key": key.String()}}},
	}
	for name, value := range ownership.Stamp(key, 1, "d").Freeform {
		if name != freeformGeneration && name != freeformSpecDigest {
			cases[name] = Tags{Freeform: map[string]string{name: value}}
		}
	}
	for name, tags := range cases {
		t.Run(name, func(t *testing.T) {
			store := integrationStore(t)
			cloud := &fakeWidgets{cloud: map[string]widget{"a": {Size: 1, Tags: tags}}}
			controller, _ := newController(t, store, cloud, TagModeFreeform)
			put(t, store, "a", 1, PolicyEnforce, 3)
			result, err := controller.Reconcile(t.Context(), 7)
			status, ok, statusErr := store.GetStatus(t.Context(), key)
			if err != nil || statusErr != nil || !ok || !status.Foreign || result.Foreign != 1 || cloud.applies != 0 {
				t.Fatalf("result=%+v status=%+v err=%v statusErr=%v writes=%d", result, status, err, statusErr, cloud.applies)
			}
		})
	}
}
