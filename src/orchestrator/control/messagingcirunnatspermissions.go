// Port of src/TerraScale.Orchestrator/Messaging/CiRunnerNatsPermissions.cs.
package control

import (
	"errors"
	"sort"
)

// CiRunnerNatsPermissionPlan mirrors the C# record.
type CiRunnerNatsPermissionPlan struct {
	Consumer      string
	FilterSubject string
	Publish       []string
	Subscribe     []string
}

// NewCiRunnerNatsPermissionPlan mirrors the C# constructor (ordinal sorting).
func NewCiRunnerNatsPermissionPlan(
	consumer string,
	filterSubject string,
	publish []string,
	subscribe []string,
) *CiRunnerNatsPermissionPlan {
	orderedPublish := append([]string(nil), publish...)
	sort.Strings(orderedPublish)
	orderedSubscribe := append([]string(nil), subscribe...)
	sort.Strings(orderedSubscribe)

	return &CiRunnerNatsPermissionPlan{
		Consumer:      consumer,
		FilterSubject: filterSubject,
		Publish:       orderedPublish,
		Subscribe:     orderedSubscribe,
	}
}

// CiRunnerNatsPermissions mirrors the C# static class: the exact NATS.Net 2.7.2
// subjects required by a runner agent after a controller has provisioned its
// durable consumer. Job containers never receive this identity.
var CiRunnerNatsPermissions ciRunnerNatsPermissions

type ciRunnerNatsPermissions struct{}

// Create mirrors CiRunnerNatsPermissions.Create.
func (ciRunnerNatsPermissions) Create(
	topology *GlobalNatsTopology,
	zone string,
	runner string,
) (*CiRunnerNatsPermissionPlan, error) {
	if topology == nil {
		return nil, errors.New("(Parameter 'topology')")
	}

	consumer, err := topology.CiJobConsumer(zone, runner)
	if err != nil {
		return nil, err
	}

	if consumer.Name == "" {
		return nil, errors.New("The CI runner consumer must have a name.")
	}

	if consumer.FilterSubject == "" {
		return nil, errors.New("The CI runner consumer must have a filter subject.")
	}

	journalPrefix, err := GlobalNatsTopologyCiRunnerJournalPrefix(runner)
	if err != nil {
		return nil, err
	}

	runnerObjects := "OBJ_" + GlobalNatsTopologyRunnerBundlesBucket

	return NewCiRunnerNatsPermissionPlan(
		consumer.Name,
		consumer.FilterSubject,
		[]string{
			"$JS.ACK." + GlobalNatsTopologyCiStream + "." + consumer.Name + ".>",
			"$JS.API.CONSUMER.INFO." + GlobalNatsTopologyCiStream + "." + consumer.Name,
			"$JS.API.CONSUMER.MSG.NEXT." + GlobalNatsTopologyCiStream + "." + consumer.Name,
			"$JS.API.CONSUMER.CREATE." + runnerObjects + ".*.$O." + GlobalNatsTopologyRunnerBundlesBucket + ".C.*",
			"$JS.API.CONSUMER.DELETE." + runnerObjects + ".*",
			"$JS.API.DIRECT.GET.KV_" + GlobalNatsTopologyRunnerJobsBucket + ".$KV." +
				GlobalNatsTopologyRunnerJobsBucket + "." + journalPrefix + ".*",
			"$JS.API.DIRECT.GET." + runnerObjects,
			"$JS.API.STREAM.INFO.KV_" + GlobalNatsTopologyRunnerJobsBucket,
			"$JS.API.STREAM.INFO." + runnerObjects,
			"$JS.FC." + runnerObjects + ".>",
			"$KV." + GlobalNatsTopologyRunnerJobsBucket + "." + journalPrefix + ".*",
			"$O." + GlobalNatsTopologyRunnerBundlesBucket + ".C.*",
			"$O." + GlobalNatsTopologyRunnerBundlesBucket + ".M.*",
		},
		[]string{"_INBOX.>"}), nil
}
