package fleet

import (
	"fmt"
	"io"
	"strings"
)

func PrintPlan(w io.Writer, reports []Report) error {
	for _, report := range reports {
		if _, err := fmt.Fprintf(w, "%s %s\n", report.Name, report.Scope); err != nil {
			return err
		}
		for _, c := range report.Checks {
			details := c.Details
			if len(details) == 0 {
				details = []string{"-"}
			}
			for i, detail := range details {
				kind, state := c.Kind, string(c.State)
				if i > 0 {
					kind, state = "", ""
				}
				if _, err := fmt.Fprintf(w, "  %-17s %-8s %s\n", kind, state, detail); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func PrintStatus(w io.Writer, reports []Report) error {
	for _, report := range reports {
		counts := map[State]int{}
		byState := map[State][]string{}
		for _, c := range report.Checks {
			counts[c.State]++
			byState[c.State] = append(byState[c.State], c.Kind)
		}
		line := fmt.Sprintf("%-4s %-22s ok %d  foreign %d  differs %d  missing %d", report.Name, report.Scope, counts[Ok], counts[Foreign], counts[Differs], counts[Missing])
		for _, state := range []State{Differs, Missing} {
			if len(byState[state]) > 0 {
				line += fmt.Sprintf("  %s: %s", state, strings.Join(byState[state], ", "))
			}
		}
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}
