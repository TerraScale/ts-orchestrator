package alertdelivery

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/gofrs/flock"
)

type journeyObservation struct {
	sync.RWMutex
	at     time.Time
	result string
	path   string
}

type journeyState struct {
	At     time.Time `json:"at"`
	Result string    `json:"result"`
	Next   time.Time `json:"next"`
}

func openJourney(path string) (*journeyObservation, error) {
	state, err := loadJourney(path)
	if err != nil {
		return nil, err
	}
	return &journeyObservation{at: state.At, result: state.Result, path: path}, nil
}

func loadJourney(path string) (journeyState, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return journeyState{}, nil
	}
	if err != nil {
		return journeyState{}, err
	}
	var state journeyState
	err = json.Unmarshal(data, &state)
	return state, err
}

func saveJourney(path string, state journeyState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".journey-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (j *journeyObservation) refresh(ctx context.Context, client *http.Client) (time.Duration, error) {
	lock := flock.New(j.path + ".lock")
	locked, err := lock.TryLock()
	if err != nil {
		return 30 * time.Minute, err
	}
	if !locked {
		return 30 * time.Minute, errors.New("journey refresh already reserved")
	}
	defer lock.Unlock()
	state, err := loadJourney(j.path)
	if err != nil {
		return 30 * time.Minute, err
	}
	j.Lock()
	j.at, j.result = state.At, state.Result
	j.Unlock()
	if delay := time.Until(state.Next); delay > 0 {
		return delay, nil
	}
	state.Next = time.Now().Add(30 * time.Minute)
	if err := saveJourney(j.path, state); err != nil {
		return 30 * time.Minute, err
	}
	refresh, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	result, err := readJourney(refresh, client)
	if err != nil {
		return time.Until(state.Next), err
	}
	state.At, state.Result = time.Now(), result
	if err := saveJourney(j.path, state); err != nil {
		return time.Until(state.Next), err
	}
	j.Lock()
	j.at, j.result = state.At, state.Result
	j.Unlock()
	return time.Until(state.Next), nil
}

func (j *journeyObservation) run(ctx context.Context, client *http.Client) {
	tick := time.NewTimer(0)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			delay, err := j.refresh(ctx, client)
			if err != nil && ctx.Err() == nil {
				slog.WarnContext(ctx, "Production journey observation unavailable", "error", err)
			}
			tick.Reset(delay)
		}
	}
}

func (j *journeyObservation) write(w io.Writer) {
	j.RLock()
	defer j.RUnlock()
	age := time.Since(j.at).Seconds()
	if j.at.IsZero() {
		age = 1e12
	}
	fmt.Fprintf(w, "terrascale_production_journey_observation_age_seconds %g\n%s", age, j.result)
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

func readJourney(ctx context.Context, client *http.Client) (string, error) {
	var runs struct {
		Runs []struct {
			ID         int64  `json:"id"`
			Conclusion string `json:"conclusion"`
		} `json:"workflow_runs"`
	}
	if err := githubJSON(ctx, client, "workflows/production-journey.yml/runs?status=completed&branch=main&per_page=10", &runs); err != nil {
		return "", err
	}
	for _, run := range runs.Runs[:min(len(runs.Runs), 10)] {
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
		if err := githubJSON(ctx, client, "runs/"+strconv.FormatInt(run.ID, 10)+"/jobs?per_page=100", &jobs); err != nil {
			return "", err
		}
		for _, job := range jobs.Jobs {
			if job.Name != "journey" || job.Conclusion == "skipped" || job.Completed.IsZero() {
				continue
			}
			success := 0
			if job.Conclusion == "success" {
				success = 1
			}
			return fmt.Sprintf("terrascale_production_journey_observed 1\nterrascale_production_journey_success %d\nterrascale_production_journey_completed_timestamp_seconds %d\n", success, job.Completed.Unix()), nil
		}
	}
	return "", fmt.Errorf("no executed production journey observed")
}
