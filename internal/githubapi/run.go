package githubapi

import (
	"encoding/json/v2"
	"fmt"
	"strings"
)

type jobDetail struct {
	ID      int64  `json:"id"`
	RunID   int64  `json:"run_id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Attempt int64  `json:"attempt"`
}

// RunDetail binds paginated jobs to the observed run attempt before normalizing it.
func RunDetail(repository string, runID int64, run func(...string) ([]byte, error)) ([]byte, error) {
	parts := strings.Split(repository, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.ContainsAny(repository, "?#%\\ \t\r\n") || runID <= 0 {
		return nil, fmt.Errorf("invalid GitHub repository or run ID")
	}
	endpoint := fmt.Sprintf("repos/%s/actions/runs/%d", repository, runID)
	data, err := run("api", "--hostname", "github.com", endpoint)
	if err != nil {
		return nil, fmt.Errorf("read GitHub run: %w", err)
	}
	if len(data) == 0 || len(data) > 128<<10 {
		return nil, fmt.Errorf("GitHub run response exceeds bounds")
	}
	var detail struct {
		ID         int64  `json:"id"`
		Number     int64  `json:"run_number"`
		SHA        string `json:"head_sha"`
		Branch     string `json:"head_branch"`
		Event      string `json:"event"`
		Path       string `json:"path"`
		Status     string `json:"status"`
		Conclusion string `json:"conclusion"`
		Attempt    int64  `json:"run_attempt"`
		Repository struct {
			Name string `json:"full_name"`
		} `json:"repository"`
		HeadRepository struct {
			Name string `json:"full_name"`
		} `json:"head_repository"`
	}
	if err := json.Unmarshal(data, &detail); err != nil {
		return nil, fmt.Errorf("decode GitHub run: %w", err)
	}
	if detail.ID != runID || detail.Attempt <= 0 || !strings.EqualFold(detail.Repository.Name, repository) || !strings.EqualFold(detail.HeadRepository.Name, repository) {
		return nil, fmt.Errorf("GitHub run identity does not match requested repository and run")
	}
	if detail.Branch != "main" || (detail.Event != "push" && detail.Event != "schedule" && detail.Event != "workflow_dispatch") {
		return nil, fmt.Errorf("GitHub release proof must originate from a main branch push, schedule, or workflow dispatch")
	}
	workflow, ok := strings.CutPrefix(detail.Path, ".github/workflows/")
	if !ok || workflow == "" || workflow == "." || workflow == ".." || strings.ContainsAny(workflow, "/\\@?#\r\n") {
		return nil, fmt.Errorf("invalid GitHub workflow path")
	}
	status, err := normalizedStatus(detail.Status, detail.Conclusion)
	if err != nil {
		return nil, err
	}
	data, err = run("api", "--hostname", "github.com", "--paginate", "--slurp", fmt.Sprintf("%s/attempts/%d/jobs?per_page=100", endpoint, detail.Attempt))
	if err != nil {
		return nil, fmt.Errorf("read GitHub jobs: %w", err)
	}
	if len(data) == 0 || len(data) > 4<<20 {
		return nil, fmt.Errorf("GitHub jobs response exceeds bounds")
	}
	var pages []struct {
		Jobs []struct {
			ID         int64  `json:"id"`
			RunID      int64  `json:"run_id"`
			Name       string `json:"name"`
			Status     string `json:"status"`
			Conclusion string `json:"conclusion"`
			Attempt    int64  `json:"run_attempt"`
		} `json:"jobs"`
	}
	if err := json.Unmarshal(data, &pages); err != nil {
		return nil, fmt.Errorf("decode GitHub jobs: %w", err)
	}
	if len(pages) == 0 {
		return nil, fmt.Errorf("GitHub jobs response has no pages")
	}
	jobs := make([]jobDetail, 0)
	for _, page := range pages {
		if page.Jobs == nil {
			return nil, fmt.Errorf("GitHub jobs page has no jobs array")
		}
		for _, job := range page.Jobs {
			if job.ID <= 0 || job.RunID != runID || job.Attempt != detail.Attempt {
				return nil, fmt.Errorf("GitHub job identity does not match run attempt")
			}
			jobStatus, err := normalizedStatus(job.Status, job.Conclusion)
			if err != nil {
				return nil, err
			}
			jobs = append(jobs, jobDetail{job.ID, job.RunID, job.Name, jobStatus, job.Attempt})
		}
	}
	return json.Marshal(struct {
		RunID     int64       `json:"run_id"`
		RunNumber int64       `json:"run_number"`
		HeadSHA   string      `json:"head_sha"`
		Workflow  string      `json:"workflow"`
		Status    string      `json:"status"`
		Jobs      []jobDetail `json:"jobs"`
	}{detail.ID, detail.Number, detail.SHA, workflow, status, jobs})
}

func normalizedStatus(status, conclusion string) (string, error) {
	switch status {
	case "completed":
		switch conclusion {
		case "success", "failure", "neutral", "cancelled", "skipped", "timed_out", "action_required", "stale", "startup_failure":
			return conclusion, nil
		}
	case "queued", "in_progress", "waiting", "requested", "pending":
		if conclusion == "" {
			return status, nil
		}
	}
	return "", fmt.Errorf("invalid GitHub run or job status")
}
