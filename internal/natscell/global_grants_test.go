package natscell

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/globalcontrol"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func TestSubjectCoversMatchesNATSWildcards(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		grant, subject string
		covers         bool
	}{
		{"ts.global.v1.>", "ts.global.v1.>", true},
		{"ts.global.>", "ts.global.v1.>", true},
		{">", "ts.control.global.>", true},
		{"ts.control.*.>", "ts.control.global.>", true},
		{"ts.control.gru.>", "ts.control.global.>", false},
		{"ts.control.global.*", "ts.control.global.>", false},
		{"ts.control.global.lease", "ts.control.global.>", false},
		{"ts.global.v1", "ts.global.v1.>", false},
	} {
		if got := subjectCovers(tc.grant, tc.subject); got != tc.covers {
			t.Errorf("subjectCovers(%q, %q) = %v, want %v", tc.grant, tc.subject, got, tc.covers)
		}
	}
}

func TestOnlyHomeControllersCarryGlobalGrants(t *testing.T) {
	t.Parallel()

	public, _ := newUserIdentity(t)
	regional, err := userPermissions("gru", NKeyGrant{PublicKey: public, Role: "controller"})
	if err != nil {
		t.Fatal(err)
	}
	home, err := userPermissions("gru", NKeyGrant{PublicKey: public, Role: "controller", Global: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range GlobalControllerPublishes() {
		if grantsCover(regional.Publish.Allow, subject) {
			t.Errorf("regional controller may publish %q", subject)
		}
		if !slices.Contains(home.Publish.Allow, subject) {
			t.Errorf("home controller lacks %q", subject)
		}
	}
	for _, role := range []string{"host", "operator"} {
		if _, err := userPermissions("gru", NKeyGrant{PublicKey: public, Role: role, Node: "node-a", Global: true}); err == nil {
			t.Errorf("%s accepted global home grants", role)
		}
	}
	keys := newTestRegionKeys(t)
	root := t.TempDir()
	for name, tc := range map[string]struct {
		publish []string
		ok      bool
	}{
		"unrestricted": {nil, true},
		"regional":     {[]string{protocol.Regional("gru", ">"), protocol.Control("gru", ">"), "$JS.API.>"}, false},
		"home":         {append([]string{protocol.Regional("gru", ">")}, GlobalControllerPublishes()...), true},
		"lease only":   {[]string{protocol.Control(protocol.GlobalScope, ">")}, false},
		"wildcard":     {[]string{">"}, true},
	} {
		path := testJWTUserCredentials(t, root, name+".creds", keys.cell, keys.cellID, tc.publish, nil)
		err := ValidateGlobalControllerPermissions(Config{Cell: "gru", CredentialsFile: path})
		if (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrMissingGlobalGrants)) {
			t.Errorf("%s credentials preflight = %v, want ok=%v", name, err, tc.ok)
		}
	}
}

// TestGlobalHomeNeedsGlobalGrantsUnderRestrictedCredentials runs the global
// authority and writer as a permission-restricted controller user, which the
// earlier tests (unrestricted embedded servers) never did. Without the home
// grants the preflight refuses before any retry loop; with them the global
// lease, the per-peer mirror consumer and a roster write all succeed.
func TestGlobalHomeNeedsGlobalGrantsUnderRestrictedCredentials(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	regionalPublic, regionalSeed := newUserIdentity(t)
	homePublic, homeSeed := newUserIdentity(t)
	server, err := Start(ctx, Config{Cell: "gru", Instance: "one", Replicas: 1, Lab: true, NKeySeedFile: homeSeed,
		Embedded: &Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "store"), Users: []NKeyGrant{
			{PublicKey: regionalPublic, Role: "controller"}, {PublicKey: homePublic, Role: "controller", Global: true},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	regionalConfig := Config{Cell: "gru", Instance: "regional", Replicas: 1, Lab: true, URL: server.URL(),
		NKeySeedFile: regionalSeed, Embedded: &Embedded{Users: []NKeyGrant{{PublicKey: regionalPublic, Role: "controller"}}}}
	if err := ValidateGlobalControllerPermissions(regionalConfig); !errors.Is(err, ErrMissingGlobalGrants) {
		t.Fatalf("regional controller preflight = %v, want ErrMissingGlobalGrants", err)
	}
	homeConfig := Config{Cell: "gru", Embedded: &Embedded{Users: []NKeyGrant{{PublicKey: homePublic, Role: "controller", Global: true}}},
		NKeySeedFile: homeSeed}
	if err := ValidateGlobalControllerPermissions(homeConfig); err != nil {
		t.Fatalf("home controller preflight: %v", err)
	}
	regionalConfig.Embedded = nil
	regional, err := Start(ctx, regionalConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = regional.Close() })

	js := server.JetStream()
	global, err := authority.Start(ctx, js, authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Scope: protocol.GlobalScope, CandidateID: "0000000000RD0JZ6JW4K5EHN9F", Replicas: 1,
		LeaseDuration: 5 * time.Second, RenewInterval: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("home controller global authority: %v", err)
	}
	t.Cleanup(func() { _ = global.Close() })
	for !global.Current().CanMutate() {
		if ctx.Err() != nil {
			t.Fatal("home controller never held the global lease")
		}
		time.Sleep(20 * time.Millisecond)
	}
	writer, err := globalcontrol.OpenHome(ctx, js, "gru", []string{"sfo"}, 1, global)
	if err != nil {
		t.Fatalf("home controller opened the global stream: %v", err)
	}
	roster := globalcontrol.Roster{Generation: 1, HomeRegion: "gru", Regions: []globalcontrol.RosterEntry{
		{Cell: "gru", OCIRegion: "sa-saopaulo-1", State: globalcontrol.RegionActive},
		{Cell: "sfo", OCIRegion: "us-sanjose-1", State: globalcontrol.RegionActive},
	}}
	if _, err := writer.PutRoster(ctx, global.Current().Epoch, roster); err != nil {
		t.Fatalf("home controller global write: %v", err)
	}
	stream, err := js.Stream(ctx, globalcontrol.StreamName)
	if err != nil {
		t.Fatal(err)
	}
	consumer, err := stream.PushConsumer(ctx, protocol.GlobalMirrorConsumer("sfo"))
	if err != nil || consumer.CachedInfo().Config.DeliverSubject != protocol.InterRegionGlobalDeliverSubject("sfo") {
		t.Fatalf("home did not create the fixed-delivery mirror consumer: %v", err)
	}

	// The same code under the regional controller's credentials is denied:
	// these are exactly the publishes the review found would fail.
	for _, subject := range []string{protocol.Control(protocol.GlobalScope, "lease"), protocol.GlobalState("roster", "current")} {
		publishCtx, publishCancel := context.WithTimeout(ctx, time.Second)
		_, err := regional.JetStream().Publish(publishCtx, subject, []byte("x"))
		publishCancel()
		if err == nil {
			t.Fatalf("regional controller published %q", subject)
		}
	}
}

// A deny that only partly overlaps the global namespace still blocks a
// global publish; an unrelated deny does not.
func TestSubjectsIntersect(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		left, right string
		want        bool
	}{
		{"ts.*.global.lease", "ts.control.global.>", true},
		{"ts.control.global.>", "ts.control.global.lease", true},
		{"private.>", "ts.control.global.>", false},
		{"ts.global.v1.*", "ts.global.v1.>", true},
		{"ts.global", "ts.global.v1.>", false},
		{"ts.*", "ts.global.v1.>", false},
		{"*.*.*", "a.>", true},
	} {
		if got := subjectsIntersect(tc.left, tc.right); got != tc.want {
			t.Errorf("subjectsIntersect(%q, %q) = %v, want %v", tc.left, tc.right, got, tc.want)
		}
	}
	if globalPublishGranted(nil, []string{"ts.*.global.lease"}) == nil {
		t.Fatal("a partially overlapping deny passed the global grant preflight")
	}
	// No allow list means unrestricted publishing subject to the denies.
	if err := globalPublishGranted(nil, []string{"private.>"}); err != nil {
		t.Fatalf("an unrelated deny without an allow list = %v", err)
	}
}
