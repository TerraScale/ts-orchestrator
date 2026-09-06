package controltransition

import "testing"

func TestDeliveryRefusesAmbiguousIdentityAndWritablePaths(t *testing.T) {
	valid := Delivery{TransitionID: "first-r3", PlanFile: "/etc/transition.json", ReceiptPrivateKeyFile: "/etc/receipt.pem"}
	for name, mutate := range map[string]func(*Delivery){
		"missing identity":     func(d *Delivery) { d.TransitionID = "" },
		"missing file":         func(d *Delivery) { d.PlanFile = "" },
		"missing receipt key":  func(d *Delivery) { d.ReceiptPrivateKeyFile = "" },
		"relative":             func(d *Delivery) { d.PlanFile = "plan.json" },
		"relative key":         func(d *Delivery) { d.ReceiptPrivateKeyFile = "key.pem" },
		"unclean":              func(d *Delivery) { d.PlanFile = "/etc/../plan.json" },
		"store child":          func(d *Delivery) { d.PlanFile = "/data/control/plan.json" },
		"store parent":         func(d *Delivery) { d.PlanFile = "/data" },
		"key in store":         func(d *Delivery) { d.ReceiptPrivateKeyFile = "/data/control/key.pem" },
		"key is plan":          func(d *Delivery) { d.ReceiptPrivateKeyFile = d.PlanFile },
		"key is plan ancestor": func(d *Delivery) { d.ReceiptPrivateKeyFile = "/etc" },
	} {
		t.Run(name, func(t *testing.T) {
			d := valid
			mutate(&d)
			if d.Validate("/data/control") == nil {
				t.Fatal("unsafe delivery accepted")
			}
		})
	}
	if (Delivery{}).Validate("/data/control") != nil {
		t.Fatal("absent optional delivery refused")
	}
	if valid.Validate("/data/control") != nil {
		t.Fatal("separate delivery refused")
	}
}
