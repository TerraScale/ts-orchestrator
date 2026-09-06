package controltransition

import "testing"

func TestDeliveryRefusesAmbiguousIdentityAndWritablePaths(t *testing.T) {
	for name, d := range map[string]Delivery{
		"missing identity": {PlanFile: "/etc/transition.json"},
		"missing file":     {TransitionID: "first-r3"},
		"relative":         {TransitionID: "first-r3", PlanFile: "plan.json"},
		"unclean":          {TransitionID: "first-r3", PlanFile: "/etc/../plan.json"},
		"store child":      {TransitionID: "first-r3", PlanFile: "/data/control/plan.json"},
		"store parent":     {TransitionID: "first-r3", PlanFile: "/data"},
	} {
		t.Run(name, func(t *testing.T) {
			if d.Validate("/data/control") == nil {
				t.Fatal("unsafe delivery accepted")
			}
		})
	}
	if (Delivery{}).Validate("/data/control") != nil {
		t.Fatal("absent optional delivery refused")
	}
	if (Delivery{TransitionID: "first-r3", PlanFile: "/etc/transition.json"}).Validate("/data/control") != nil {
		t.Fatal("separate delivery refused")
	}
}
