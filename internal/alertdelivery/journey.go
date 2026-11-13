package alertdelivery

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

var journeyCache struct {
	sync.Mutex
	at     time.Time
	result string
}

func writeJourney(ctx context.Context, client *http.Client, w io.Writer) {
	journeyCache.Lock()
	defer journeyCache.Unlock()
	if time.Since(journeyCache.at) >= 5*time.Minute {
		journeyCache.result = readJourney(ctx, client)
		journeyCache.at = time.Now()
	}
	fmt.Fprint(w, journeyCache.result)
}

func githubJSON(ctx context.Context, client *http.Client, path string, out any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/TerraScale/terrascale/actions/"+path, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("journey metadata unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return fmt.Errorf("journey metadata too large")
	}
	return json.Unmarshal(data, out)
}

func readJourney(ctx context.Context, client *http.Client) string {
	var runs struct {
		Runs []struct {
			ID         int64  `json:"id"`
			Conclusion string `json:"conclusion"`
		} `json:"workflow_runs"`
	}
	if githubJSON(ctx, client, "workflows/production-journey.yml/runs?status=completed&branch=main&per_page=10", &runs) != nil {
		return "terrascale_production_journey_observed 0\n"
	}
	for _, run := range runs.Runs {
		if run.Conclusion == "skipped" {
			continue
		}
		var jobs struct {
			Jobs []struct {
				Name       string    `json:"name"`
				Conclusion string    `json:"conclusion"`
				Completed  time.Time `json:"completed_at"`
			} `json:"jobs"`
		}
		if githubJSON(ctx, client, "runs/"+strconv.FormatInt(run.ID, 10)+"/jobs?per_page=100", &jobs) != nil {
			break
		}
		for _, job := range jobs.Jobs {
			if job.Name != "journey" || job.Conclusion == "skipped" || job.Completed.IsZero() {
				continue
			}
			success := 0
			if job.Conclusion == "success" {
				success = 1
			}
			return fmt.Sprintf("terrascale_production_journey_observed 1\nterrascale_production_journey_success %d\nterrascale_production_journey_completed_timestamp_seconds %d\n", success, job.Completed.Unix())
		}
	}
	return "terrascale_production_journey_observed 0\n"
}
