package dashboard

import "github.com/a-h/templ"

// table is a server-rendered data table. Pages build it in Go and render it
// with dataTable, so each new table adds data, not template code.
type table struct {
	Caption string   // the accessible name; the section heading is visible
	Headers []string // column headers; the first column is the row header
	Rows    [][]cell
	Empty   string // shown instead of the table when Rows is empty
}

// cell is one table cell. Href makes it a link, Status a status badge
// (the existing ok/warn/bad/idle/info classes), Title its tooltip. Extra is
// markup after the text, for a second badge or a component such as ago.
type cell struct {
	Text, Href, Status, Title string
	Extra                     templ.Component
}

func textCell(text string) cell { return cell{Text: text} }
