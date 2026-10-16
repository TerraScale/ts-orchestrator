package dashboard

import (
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/regionview"
)

func (current view) resourcesForNode(node regionview.Node, local bool) *regionview.ResourceView {
	if node.Resources != nil {
		return node.Resources
	}
	if !local {
		return new(regionview.ResourceView)
	}
	var history observability.HistorySource
	if current.Journal != nil {
		history = current.Journal.History
	}
	return regionview.CollectResources(node, history, current.Now)
}

func (current view) resourceNodes() []regionview.Node {
	for _, summary := range current.topologySummaries() {
		if summary.Region != current.localRegion() {
			continue
		}
		nodes := slices.Clone(summary.Nodes)
		for index := range nodes {
			nodes[index].Resources = current.resourcesForNode(nodes[index], true)
		}
		return nodes
	}
	return nil
}

func (current view) detailHostNode() regionview.Node {
	for _, summary := range current.topologySummaries() {
		if summary.Region != current.Path["r"] {
			continue
		}
		for _, node := range summary.Nodes {
			if node.Name == current.Path["h"] {
				node.Resources = current.resourcesForNode(node, summary.Region == current.localRegion())
				return node
			}
		}
	}
	node := regionview.Node{Name: current.Path["h"]}
	node.Resources = current.resourcesForNode(node, current.Path["r"] == current.localRegion())
	return node
}

func (current view) readingText(reading *regionview.Reading, unit string) string {
	if reading == nil {
		return "unavailable"
	}
	text := formatFloat(reading.Value, 0)
	switch unit {
	case "percent":
		text = formatFloat(reading.Value*100, 1) + "%"
	case "bytes":
		text = formatBytes(uint64(reading.Value))
	case "cores":
		text += " cores"
	}
	if !reading.Fresh(current.Now) {
		text += " (stale)"
	}
	return text
}

func (current view) resourceCPU(resources *regionview.ResourceView) string {
	return joinDetail(current.readingText(resources.CPU, "percent"), current.readingText(resources.CPUCores, "cores"))
}

func (current view) resourceMemory(resources *regionview.ResourceView) string {
	return joinDetail(current.readingText(resources.Memory, "percent"),
		current.readingText(resources.MemoryUsedBytes, "bytes")+" / "+current.readingText(resources.MemoryBytes, "bytes"))
}

func (current view) resourceDisk(resources *regionview.ResourceView) string {
	return joinDetail(current.readingText(resources.Disk, "percent"), itoa(len(resources.Filesystems))+" filesystems")
}

func (current view) readingStatus(reading *regionview.Reading) string {
	if reading == nil || !reading.Fresh(current.Now) {
		return "idle"
	}
	return ratioStatus(reading.Value)
}

func resourceNote(resources *regionview.ResourceView) string {
	var notes []string
	if resources.Pending {
		notes = append(notes, "Regional metric history is loading.")
	}
	if resources.Incomplete {
		notes = append(notes, "Resource collection or regional metric history is incomplete.")
	}
	return strings.Join(notes, " ")
}

// nodeHistory names authenticated whole-node series by the granted node.
func (current view) nodeHistory(metric, nameBy string) []chartSeries {
	var series []chartSeries
	for _, node := range current.resourceNodes() {
		if host := current.State.param("host"); host != "" && host != node.Name {
			continue
		}
		if current.Page.slug == "host" && node.Name != current.Path["h"] {
			continue
		}
		for _, one := range current.historyRange(metric, map[string]string{"member": strings.ToLower(node.Name)}, nameBy, false) {
			if nameBy == "" {
				one.Name = node.Name
			} else {
				one.Name = node.Name + " " + one.Name
			}
			series = append(series, one)
		}
	}
	return series
}

func (current view) nodeChart(metric, nameBy, empty string) chartSpec {
	spec := current.lineChart("line", "percent", current.nodeHistory(metric, nameBy), empty)
	spec.Min, spec.Max = new(0.0), new(1.0)
	return spec
}

func (current view) capacityWarning(resources *regionview.ResourceView) string {
	for _, reading := range []*regionview.Reading{resources.MemoryBytes, resources.MemoryUsedBytes} {
		if reading != nil && !reading.Fresh(current.Now) {
			return "Capacity includes stale measurements; inspect the filesystem table for freshness."
		}
	}
	for _, filesystem := range resources.Filesystems {
		if filesystem.SizeBytes != nil && !filesystem.SizeBytes.Fresh(current.Now) || filesystem.UsedBytes != nil && !filesystem.UsedBytes.Fresh(current.Now) {
			return "Capacity includes stale measurements; inspect the filesystem table for freshness."
		}
	}
	return ""
}

func (current view) filesystemAvailable(filesystem regionview.Filesystem) string {
	if filesystem.SizeBytes == nil || filesystem.UsedBytes == nil || !filesystem.SizeBytes.ObservedAt.Equal(filesystem.UsedBytes.ObservedAt) {
		return "unavailable"
	}
	reading := regionview.Reading{Value: max(filesystem.SizeBytes.Value-filesystem.UsedBytes.Value, 0), ObservedAt: filesystem.SizeBytes.ObservedAt}
	return current.readingText(&reading, "bytes")
}
