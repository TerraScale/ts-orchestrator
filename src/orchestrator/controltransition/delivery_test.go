package controltransition

import (
	"terrascale.tech/orchestrator/src/orchestrator/ociinstance"
	fixture "terrascale.tech/orchestrator/src/orchestrator/sandboxproviders/ociinstance"
	"testing"
)

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

func TestDeliveryQualificationIdentityIsBoundedAndSeparate(t *testing.T) {
	server, err := fixture.New(fixture.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	cfg, key, err := server.Identity("host", "sa-saopaulo-1", "/etc/oci-client.pem")
	if err != nil {
		t.Fatal(err)
	}
	clear(key)
	valid := Delivery{TransitionID: "first-r3", PlanFile: "/etc/plan.json", ReceiptPrivateKeyFile: "/etc/receipt.pem", OCIQualification: cfg.Qualification}
	if err := valid.Validate("/data/control"); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*ociinstance.QualificationConfig){
		"insecure endpoint": func(q *ociinstance.QualificationConfig) { q.Endpoint = "http://example.test" },
		"receipt key":       func(q *ociinstance.QualificationConfig) { q.ClientPrivateKeyFile = valid.ReceiptPrivateKeyFile },
		"plan file":         func(q *ociinstance.QualificationConfig) { q.ClientPrivateKeyFile = valid.PlanFile },
		"store child":       func(q *ociinstance.QualificationConfig) { q.ClientPrivateKeyFile = "/data/control/key.pem" },
		"store parent":      func(q *ociinstance.QualificationConfig) { q.ClientPrivateKeyFile = "/data" },
		"relative key":      func(q *ociinstance.QualificationConfig) { q.ClientPrivateKeyFile = "key.pem" },
	} {
		t.Run(name, func(t *testing.T) {
			d := valid
			q := *valid.OCIQualification
			mutate(&q)
			d.OCIQualification = &q
			if d.Validate("/data/control") == nil {
				t.Fatal("unsafe qualification accepted")
			}
		})
	}
}
