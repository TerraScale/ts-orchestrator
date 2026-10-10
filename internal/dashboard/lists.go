package dashboard

import (
	"slices"
	"strconv"
)

// drillRows is how many rows one page of the node or volume list shows.
const drillRows = 50

// nodeSorts are the nodes list's sort keys. name orders by region, then node;
// the others order the largest value first.
var nodeSorts = []string{"name", "cpu", "memory", "disk", "network"}

// pager is one page of a list: rows From up to To of Total, on page Page of Pages.
type pager struct {
	Page, Pages, From, To, Total int
}

// newPager clamps the requested page to the list.
func newPager(total, requested int) pager {
	pages := max(1, (total+drillRows-1)/drillRows)
	page := min(max(requested, 1), pages)
	from := (page - 1) * drillRows
	return pager{Page: page, Pages: pages, From: from, To: min(from+drillRows, total), Total: total}
}

// pageParam reads the 1-based page number; a missing or invalid one is page 1.
func pageParam(current view) int {
	page, _ := strconv.Atoi(current.State.param("page"))
	return page
}

// regionFilterParam is the region a list filters to, or "" for every region.
func regionFilterParam(current view) string {
	if cell := current.State.param("region"); validRegion(cell) {
		return cell
	}
	return ""
}

// sortParam is the nodes list's sort key; an unknown key sorts by name.
func sortParam(current view) string {
	if key := current.State.param("sort"); slices.Contains(nodeSorts, key) {
		return key
	}
	return "name"
}

// nodeList is one page of the nodes list with the filters it was built with.
type nodeList struct {
	Rows   []nodeEntry
	Pager  pager
	Region string
	Sort   string
}

func nodesListOf(current view) nodeList {
	list := nodeList{Region: regionFilterParam(current), Sort: sortParam(current)}
	entries := nodeEntries(current.Global, list.Region, list.Sort)
	list.Pager = newPager(len(entries), pageParam(current))
	list.Rows = entries[list.Pager.From:list.Pager.To]
	return list
}

// volumeList is one page of the volumes list.
type volumeList struct {
	Rows   []volumeEntry
	Pager  pager
	Region string
}

func volumesListOf(current view) volumeList {
	list := volumeList{Region: regionFilterParam(current)}
	entries := volumeEntries(current.Global, list.Region)
	list.Pager = newPager(len(entries), pageParam(current))
	list.Rows = entries[list.Pager.From:list.Pager.To]
	return list
}
