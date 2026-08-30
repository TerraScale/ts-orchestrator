// Port of src/TerraScale.Orchestrator/Messaging/GlobalNatsPermissions.cs.
package control

import (
	"errors"
	"fmt"
	"sort"
)

// GlobalNatsRole mirrors the C# enum.
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

// GlobalNatsPermissionPlan mirrors the C# record: ordinally sorted allowlists.
type GlobalNatsPermissionPlan struct {
	Publish   []string
	Subscribe []string
}

// NewGlobalNatsPermissionPlan mirrors the C# constructor.
func NewGlobalNatsPermissionPlan(publish, subscribe []string) *GlobalNatsPermissionPlan {
	orderedPublish := append([]string(nil), publish...)
	sort.Strings(orderedPublish)
	orderedSubscribe := append([]string(nil), subscribe...)
	sort.Strings(orderedSubscribe)

	return &GlobalNatsPermissionPlan{Publish: orderedPublish, Subscribe: orderedSubscribe}
}

// GlobalNatsPermissions mirrors the C# static class: the complete NATS subject
// permissions for one global-control role. Callers grant the returned subjects
// as an allowlist with no implicit defaults.
var GlobalNatsPermissions globalNatsPermissions

type globalNatsPermissions struct{}

// GlobalNatsPermissionsCreate mirrors GlobalNatsPermissions.Create.
func GlobalNatsPermissionsCreate(cell string, role GlobalNatsRole) (*GlobalNatsPermissionPlan, error) {
	if !messagingCellTokenIsValid(cell) {
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
		publish = append(publish, globalNatsStreamManagement(stream.Name)...)
	}

	publish = append(publish,
		"$KV."+topology.Leaders().Bucket+".authority.global",
		"$KV."+topology.Releases().Bucket+".>",
		"$KV."+topology.RunnerJobs().Bucket+"."+GlobalNatsTopologyCiRunnerJournalKeyPrefix+".*.job.>",
		GlobalNatsTopologyCiSubject(),
		GlobalNatsTopologyCiJobSubjectPrefix()+".untrusted-product.*",
		GlobalNatsTopologyCiJobSubjectPrefix()+".trusted-build.*",
		GlobalNatsTopologyCellSpecSubjectPrefix()+".*",
	)

	publish = append(publish, globalNatsKeyValueManagement(topology.Leaders().Bucket)...)
	publish = append(publish, globalNatsKeyValueManagement(topology.Releases().Bucket)...)
	publish = append(publish, globalNatsKeyValueManagement(topology.RunnerJobs().Bucket)...)
	publish = append(publish, globalNatsObjectStorePermissions(topology.Bundles().Bucket)...)
	publish = append(publish, globalNatsObjectStorePermissions(topology.RunnerBundles().Bucket)...)

	ciConsumer := topology.CiConsumer()
	ciRuntimeProofConsumer := topology.CiRuntimeProofConsumer()
	cellSpecConsumer, err := topology.CellSpecConsumer(cell)
	if err != nil {
		return nil, err
	}

	publish = append(publish, globalNatsConsumerPermissions(
		GlobalNatsTopologyCiStream, ciConsumer.Name, ciConsumer.FilterSubject)...)
	publish = append(publish, globalNatsConsumerPermissions(
		GlobalNatsTopologyCiStream, ciRuntimeProofConsumer.Name, ciRuntimeProofConsumer.FilterSubject)...)
	publish = append(publish, globalNatsConsumerPermissions(
		GlobalNatsTopologyCellSpecStream, cellSpecConsumer.Name, cellSpecConsumer.FilterSubject)...)
	publish = append(publish, globalNatsKeyValueWatchPermissions(topology.Releases().Bucket)...)
	publish = append(publish, globalNatsCiRunnerConsumerPermissions()...)

	return NewGlobalNatsPermissionPlan(publish, []string{"_INBOX.>"}), nil
}

func globalNatsStreamManagement(stream string) []string {
	return []string{
		"$JS.API.STREAM.CREATE." + stream,
		"$JS.API.STREAM.UPDATE." + stream,
		"$JS.API.STREAM.INFO." + stream,
	}
}

func globalNatsKeyValueManagement(bucket string) []string {
	return []string{
		"$JS.API.STREAM.CREATE.KV_" + bucket,
		"$JS.API.STREAM.UPDATE.KV_" + bucket,
		"$JS.API.STREAM.INFO.KV_" + bucket,
		"$JS.API.DIRECT.GET.KV_" + bucket,
	}
}

func globalNatsObjectStorePermissions(bucket string) []string {
	stream := "OBJ_" + bucket
	return []string{
		"$JS.API.STREAM.CREATE." + stream,
		"$JS.API.STREAM.UPDATE." + stream,
		"$JS.API.STREAM.INFO." + stream,
		"$JS.API.STREAM.PURGE." + stream,
		"$JS.API.STREAM.MSG.GET." + stream,
		"$JS.API.DIRECT.GET." + stream,
		"$JS.API.CONSUMER.CREATE." + stream + ".*.$O." + bucket + ".C.*",
		"$JS.API.CONSUMER.DELETE." + stream + ".*",
		"$JS.FC." + stream + ".>",
		"$O." + bucket + ".C.>",
		"$O." + bucket + ".M.>",
	}
}

// globalNatsKeyValueWatchPermissions mirrors KeyValueWatchPermissions: KV key
// enumeration (retention/pruning scans and directory watches) as implemented by
// NATS.Net 2.7.2 creates an ephemeral ordered push consumer via one
// $JS.API.CONSUMER.CREATE.KV_{bucket}.<ephemeral>.<filter> publish and receives
// every entry on a fresh _INBOX.<nuid>.* subscription. It never creates
// durable consumers, never pulls (MSG.NEXT), never acknowledges ($JS.ACK), and
// never answers flow control ($JS.FC).
func globalNatsKeyValueWatchPermissions(bucket string) []string {
	return []string{
		"$JS.API.CONSUMER.CREATE.KV_" + bucket,
		"$JS.API.CONSUMER.CREATE.KV_" + bucket + ".>",
	}
}

func globalNatsConsumerPermissions(stream, consumer, filterSubject string) []string {
	return []string{
		"$JS.API.CONSUMER.CREATE." + stream + "." + consumer,
		"$JS.API.CONSUMER.CREATE." + stream + "." + consumer + "." + filterSubject,
		"$JS.API.CONSUMER.DURABLE.CREATE." + stream + "." + consumer,
		"$JS.API.CONSUMER.DURABLE.CREATE." + stream + "." + consumer + "." + filterSubject,
		"$JS.API.CONSUMER.INFO." + stream + "." + consumer,
		"$JS.API.CONSUMER.MSG.NEXT." + stream + "." + consumer,
		"$JS.ACK." + stream + "." + consumer + ".>",
		"$JS.FC." + stream + "." + consumer + ".>",
	}
}

func globalNatsCiRunnerConsumerPermissions() []string {
	filter := GlobalNatsTopologyCiJobSubjectPrefix() + ".*.*"
	return []string{
		"$JS.API.CONSUMER.CREATE." + GlobalNatsTopologyCiStream + ".*." + filter,
		"$JS.API.CONSUMER.DURABLE.CREATE." + GlobalNatsTopologyCiStream + ".*." + filter,
		"$JS.API.CONSUMER.INFO." + GlobalNatsTopologyCiStream + ".*",
		"$JS.API.CONSUMER.MSG.NEXT." + GlobalNatsTopologyCiStream + ".*",
		"$JS.ACK." + GlobalNatsTopologyCiStream + ".*.>",
		"$JS.FC." + GlobalNatsTopologyCiStream + ".*.>",
	}
}
