package swarmruntime

import (
	"testing"

	"github.com/moby/swarmkit/v2/api"
)

func TestHostnameClaimedByOtherRefusesTakeover(t *testing.T) {
	owner := &api.Service{Spec: api.ServiceSpec{Annotations: api.Annotations{Name: "ts-auth",
		Labels: map[string]string{LabelHostnames: "auth.example.com,login.example.com"}}}}
	services := []*api.Service{owner}
	if err := hostnameClaimedByOther(services, "evil", []string{"login.example.com"}); err == nil {
		t.Fatal("another service took over login.example.com")
	}
	if err := hostnameClaimedByOther(services, "ts-auth", []string{"auth.example.com"}); err != nil {
		t.Fatalf("owner re-apply refused: %v", err)
	}
	if err := hostnameClaimedByOther(services, "api", []string{"api.example.com"}); err != nil {
		t.Fatalf("free hostname refused: %v", err)
	}
	if err := hostnameClaimedByOther(services, "worker", nil); err != nil {
		t.Fatalf("service without hostnames refused: %v", err)
	}
}
