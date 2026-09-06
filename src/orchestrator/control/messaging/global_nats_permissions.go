package messaging

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/control/internal/shared"
	"terrascale.tech/orchestrator/src/orchestrator/natspolicy"
)

// GlobalNatsRole identifies one global-control role.
type GlobalNatsRole int

const (
	GlobalNatsRoleCellDirectoryPublisher GlobalNatsRole = 0
	GlobalNatsRoleCellDirectoryReader    GlobalNatsRole = 1
	GlobalNatsRoleCellDirectoryService   GlobalNatsRole = 2
	GlobalNatsRoleGlobalAuthority        GlobalNatsRole = 3
)

func (r GlobalNatsRole) String() string {
	switch r {
	case GlobalNatsRoleCellDirectoryPublisher:
		return "CellDirectoryPublisher"
	case GlobalNatsRoleCellDirectoryReader:
		return "CellDirectoryReader"
	case GlobalNatsRoleCellDirectoryService:
		return "CellDirectoryService"
	case GlobalNatsRoleGlobalAuthority:
		return "GlobalAuthority"
	default:
		return fmt.Sprintf("%d", int(r))
	}
}

// GlobalNatsPermissionPlan is a pair of ordinally sorted allowlists.
type GlobalNatsPermissionPlan struct {
	Publish   []string
	Subscribe []string
}

// NewGlobalNatsPermissionPlan copies the allowlists and sorts them ordinally.
func NewGlobalNatsPermissionPlan(publish, subscribe []string) *GlobalNatsPermissionPlan {
	orderedPublish := append([]string(nil), publish...)
	sort.Strings(orderedPublish)
	orderedSubscribe := append([]string(nil), subscribe...)
	sort.Strings(orderedSubscribe)

	return &GlobalNatsPermissionPlan{Publish: orderedPublish, Subscribe: orderedSubscribe}
}

// GlobalNatsPermissions computes the complete NATS subject permissions for one
// global-control role. Callers grant the returned subjects as an allowlist
// with no implicit defaults.
var GlobalNatsPermissions globalNatsPermissions

type globalNatsPermissions struct{}

func GlobalNatsPermissionsCreate(cell string, role GlobalNatsRole) (*GlobalNatsPermissionPlan, error) {
	if !shared.MessagingCellTokenIsValid(cell) {
		return nil, errors.New(
			"The global NATS permission cell is not a lowercase DNS-style token. (Parameter 'cell')")
	}

	switch role {
	case GlobalNatsRoleCellDirectoryPublisher:
		advertisementKey, err := GlobalNatsTopologyCellAdvertisementKey(cell)
		if err != nil {
			return nil, err
		}

		// The publisher never publishes the directory query subject: only the
		// GRU directory service answers there (readers request, the service
		// replies), so this role must not carry a publish grant for it.
		return NewGlobalNatsPermissionPlan(
			[]string{
				"$JS.API.CONSUMER.CREATE.KV_GLOBAL_CELLS.>",
				"$JS.API.DIRECT.GET.KV_GLOBAL_CELLS",
				"$JS.API.DIRECT.GET.KV_GLOBAL_CELLS.>",
				"$JS.API.STREAM.INFO.KV_GLOBAL_CELLS",
				"$JS.FC.KV_GLOBAL_CELLS.>",
				"$KV.GLOBAL_CELLS." + advertisementKey,
			},
			[]string{"$KV.GLOBAL_CELLS.>", "_INBOX.>"}), nil
	case GlobalNatsRoleCellDirectoryReader:
		return NewGlobalNatsPermissionPlan(
			[]string{GlobalNatsTopologyCellDirectorySubject()},
			[]string{"_INBOX.>"}), nil
	case GlobalNatsRoleCellDirectoryService:
		return NewGlobalNatsPermissionPlan(
			[]string{"_INBOX.>", "_R_.>"},
			[]string{"$SRV.>", GlobalNatsTopologyCellDirectorySubject()}), nil
	case GlobalNatsRoleGlobalAuthority:
		return globalNatsPermissionsAuthority(cell)
	default:
		return nil, fmt.Errorf(
			"Specified argument was out of the range of valid values. (Parameter 'role')\nActual value was %d.",
			int(role))
	}
}

func globalNatsPermissionsAuthority(cell string) (*GlobalNatsPermissionPlan, error) {
	topology, err := NewGlobalNatsTopology(3)
	if err != nil {
		return nil, err
	}

	streams := topology.Streams()
	publish := []string{}
	for _, stream := range streams {
		publish = append(publish, globalNatsStreamReadPermissions(stream.Name)...)
	}

	publish = append(publish,
		"$KV."+topology.Leaders().Bucket+".authority.global",
		"$KV."+topology.Leaders().Bucket+".security.rotation.state",
		"$KV."+topology.Leaders().Bucket+".security.rotation.barrier",
		"$KV."+topology.Leaders().Bucket+".restore.drill.state",
		"$KV."+topology.Leaders().Bucket+".restore.drill.barrier",
		"$KV."+topology.Leaders().Bucket+".placement.proposal.state",
		"$KV."+topology.Leaders().Bucket+".placement.proposal.barrier",
		"orch.placement.host.*.stage",
		"orch.placement.host.*.accept",
		"orch.placement.host.*.drain",
		"orch.placement.host.*.readiness",
		"orch.auth.bootstrap.host.*.identity",
		"orch.auth.bootstrap.host.*.bootstrap",
		"$KV.ORCH_LEADERS.auth.bootstrap.state",
		"$KV.ORCH_LEADERS.auth.bootstrap.barrier",
		"$KV."+topology.Leaders().Bucket+".reaper.state",
		"$KV."+topology.Leaders().Bucket+".reaper.barrier",
		"$KV."+topology.MasterDeliveries().Bucket+".master.>",
		"_INBOX.>",
		GlobalNatsTopologyCellSpecSubjectPrefix()+".*",
	)

	// KV.Get uses the direct subject form; pin its suffix to writable state keys.
	for _, subject := range publish {
		if strings.HasPrefix(subject, "$KV.") {
			bucket := strings.SplitN(strings.TrimPrefix(subject, "$KV."), ".", 2)[0]
			publish = append(publish, "$JS.API.DIRECT.GET.KV_"+bucket+"."+subject)
		}
	}

	// Runtime admission reads the directory bucket through the authority
	// connection. Directory publication retains its separate identity.
	publish = append(publish, "$JS.API.STREAM.INFO.KV_"+topology.Cells().Bucket)
	publish = append(publish, globalNatsKeyValueReadPermissions(topology.Leaders().Bucket)...)
	publish = append(publish, globalNatsKeyValueReadPermissions(topology.MasterDeliveries().Bucket)...)

	cellSpecConsumer, err := topology.CellSpecConsumer(cell)
	if err != nil {
		return nil, err
	}

	publish = append(publish, globalNatsConsumerPermissions(
		GlobalNatsTopologyCellSpecStream, cellSpecConsumer.Name)...)

	return NewGlobalNatsPermissionPlan(publish, []string{"_INBOX.>", natspolicy.NatsSubjectTaxonomy.GlobalDeliverySubject()}), nil
}

func globalNatsStreamReadPermissions(stream string) []string {
	return []string{
		"$JS.API.STREAM.INFO." + stream,
	}
}

func globalNatsKeyValueReadPermissions(bucket string) []string {
	return []string{
		"$JS.API.STREAM.INFO.KV_" + bucket,
		"$JS.API.DIRECT.GET.KV_" + bucket,
		"$JS.API.STREAM.MSG.GET.KV_" + bucket,
	}
}

func globalNatsConsumerPermissions(stream, consumer string) []string {
	return []string{
		"$JS.API.CONSUMER.INFO." + stream + "." + consumer,
		"$JS.API.CONSUMER.MSG.NEXT." + stream + "." + consumer,
		"$JS.ACK." + stream + "." + consumer + ".>",
		"$JS.FC." + stream + "." + consumer + ".>",
	}
}
