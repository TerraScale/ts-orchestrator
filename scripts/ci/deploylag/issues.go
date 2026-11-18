package main

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"
)

const issueBase = forge + "ts-orchestrator/issues"
const pageMarker = "Page reserved at: "

type issue struct {
	Number      int    `json:"number"`
	Title       string `json:"title"`
	Body        string `json:"body"`
	PullRequest any    `json:"pull_request"`
}

func (a *api) syncIssue(ctx context.Context, open []issue, title, body string, active bool) error {
	for i, issue := range open {
		patch := map[string]string{"state": "closed"}
		if active && i == 0 {
			patch = map[string]string{"body": body}
		}
		if err := a.request(ctx, "PATCH", fmt.Sprintf("%s/%d", issueBase, issue.Number), a.writeToken, patch, nil); err != nil {
			return err
		}
	}
	if active && len(open) == 0 {
		return a.request(ctx, "POST", issueBase, a.writeToken, map[string]any{"title": title, "body": body, "assignees": []string{"mariogk"}}, nil)
	}
	return nil
}

func (a *api) issues(ctx context.Context, rows map[string][]string, red, unknown map[string]bool, now time.Time) ([]string, error) {
	open := map[string][]issue{}
	for page := 1; ; page++ {
		var issues []issue
		if err := a.request(ctx, "GET", fmt.Sprintf("%s?state=open&per_page=100&page=%d", issueBase, page), a.writeToken, nil, &issues); err != nil {
			return nil, err
		}
		for _, issue := range issues {
			if issue.PullRequest == nil {
				open[issue.Title] = append(open[issue.Title], issue)
			}
		}
		if len(issues) < 100 {
			break
		}
	}
	var pages, gaps []string
	run := "https://github.com/" + os.Getenv("GITHUB_REPOSITORY") + "/actions/runs/" + os.Getenv("GITHUB_RUN_ID")
	for _, x := range artifacts {
		if unknown[x.name] {
			gaps = append(gaps, rows[x.name]...)
		}
		if unknown[x.name] && !red[x.name] {
			continue
		}
		title := "Deploy lag: " + x.name
		body := "@mariogk Deployment guard is red.\n\n```text\n" + strings.Join(rows[x.name], "\n") + "\n```\n\n" + run
		reserve := false
		if red[x.name] {
			var reserved time.Time
			if len(open[title]) > 0 {
				first, _, _ := strings.Cut(open[title][0].Body, "\n")
				if timestamp, ok := strings.CutPrefix(first, pageMarker); ok {
					var err error
					reserved, err = time.Parse(time.RFC3339Nano, timestamp)
					if err != nil {
						return pages, fmt.Errorf("%s has an unreadable page reservation", title)
					}
				}
			}
			reserve = reserved.IsZero() || now.Sub(reserved) >= 30*time.Minute
			if reserve {
				reserved = now.UTC()
			}
			body = pageMarker + reserved.Format(time.RFC3339Nano) + "\n\n" + body
		}
		if err := a.syncIssue(ctx, open[title], title, body, red[x.name]); err != nil {
			return pages, err
		}
		if reserve {
			pages = append(pages, x.name)
		}
	}
	slices.Sort(gaps)
	gaps = slices.Compact(gaps)
	body := "@mariogk Deployment observation is unavailable. No lag is inferred and no page is sent for these gaps. Existing lag incidents remain open until recovery is observed.\n\n```text\n" + strings.Join(gaps, "\n") + "\n```\n\n" + run
	return pages, a.syncIssue(ctx, open["Deploy observation unavailable"], "Deploy observation unavailable", body, len(gaps) > 0)
}
