package githubapi

import (
	"encoding/json/v2"
	"reflect"
	"strings"
	"testing"
)

func TestRunDetail(t *testing.T) {
	const runJSON = `{"id":42,"run_number":7,"head_sha":"abc","head_branch":"main","event":"push","path":".github/workflows/ci.yml","status":"completed","conclusion":"success","run_attempt":2,"repository":{"full_name":"TerraScale/terrabase"},"head_repository":{"full_name":"TerraScale/terrabase"}}`
	const jobsJSON = `[{"jobs":[{"id":1,"run_id":42,"name":"build","status":"completed","conclusion":"success","run_attempt":2}]},{"jobs":[{"id":2,"run_id":42,"name":"extra","status":"completed","conclusion":"failure","run_attempt":2}]}]`
	for _, tc := range []struct {
		name, run, jobs string
		wantError       bool
	}{
		{"success with failed additional job and multiple pages", runJSON, jobsJSON, false},
		{"scheduled main", strings.Replace(runJSON, `"event":"push"`, `"event":"schedule"`, 1), jobsJSON, false},
		{"dispatched main", strings.Replace(runJSON, `"event":"push"`, `"event":"workflow_dispatch"`, 1), jobsJSON, false},
		{"wrong branch", strings.Replace(runJSON, `"head_branch":"main"`, `"head_branch":"other"`, 1), jobsJSON, true},
		{"pull request event", strings.Replace(runJSON, `"event":"push"`, `"event":"pull_request"`, 1), jobsJSON, true},
		{"pull request target event", strings.Replace(runJSON, `"event":"push"`, `"event":"pull_request_target"`, 1), jobsJSON, true},
		{"wrong run", strings.Replace(runJSON, `"id":42`, `"id":43`, 1), jobsJSON, true},
		{"wrong repository", strings.Replace(runJSON, `"full_name":"TerraScale/terrabase"`, `"full_name":"other/terrabase"`, 1), jobsJSON, true},
		{"fork", strings.Replace(runJSON, `"head_repository":{"full_name":"TerraScale/terrabase"}`, `"head_repository":{"full_name":"other/terrabase"}`, 1), jobsJSON, true},
		{"zero attempt", strings.Replace(runJSON, `"run_attempt":2`, `"run_attempt":0`, 1), jobsJSON, true},
		{"wrong job attempt", runJSON, strings.ReplaceAll(jobsJSON, `"run_attempt":2`, `"run_attempt":1`), true},
		{"wrong job run", runJSON, strings.ReplaceAll(jobsJSON, `"run_id":42`, `"run_id":43`), true},
		{"success is not a GitHub status", strings.Replace(runJSON, `"status":"completed"`, `"status":"success"`, 1), jobsJSON, true},
		{"incomplete success", strings.Replace(runJSON, `"status":"completed"`, `"status":"in_progress"`, 1), jobsJSON, true},
		{"workflow ref", strings.Replace(runJSON, "ci.yml", "ci.yml@main", 1), jobsJSON, true},
		{"nested workflow", strings.Replace(runJSON, "ci.yml", "other/ci.yml", 1), jobsJSON, true},
		{"missing page jobs", runJSON, `[{}]`, true},
		{"unpaginated object", runJSON, `{"jobs":[]}`, true},
		{"empty pages", runJSON, `[]`, true},
		{"oversized run", strings.Repeat(" ", 128<<10) + runJSON, jobsJSON, true},
		{"oversized jobs", runJSON, strings.Repeat(" ", 4<<20) + jobsJSON, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			wire, err := RunDetail("TerraScale/terrabase", 42, func(args ...string) ([]byte, error) {
				calls++
				if calls == 1 {
					if !reflect.DeepEqual(args, []string{"api", "--hostname", "github.com", "repos/TerraScale/terrabase/actions/runs/42"}) {
						t.Fatalf("run args: %v", args)
					}
					return []byte(tc.run), nil
				}
				if !reflect.DeepEqual(args, []string{"api", "--hostname", "github.com", "--paginate", "--slurp", "repos/TerraScale/terrabase/actions/runs/42/attempts/2/jobs?per_page=100"}) {
					t.Fatalf("jobs args: %v", args)
				}
				return []byte(tc.jobs), nil
			})
			if (err != nil) != tc.wantError {
				t.Fatalf("error = %v; wantError = %v", err, tc.wantError)
			}
			if tc.wantError {
				return
			}
			var got struct {
				RunID    int64       `json:"run_id"`
				Workflow string      `json:"workflow"`
				Status   string      `json:"status"`
				Jobs     []jobDetail `json:"jobs"`
			}
			if err := json.Unmarshal(wire, &got); err != nil {
				t.Fatal(err)
			}
			if got.RunID != 42 || got.Workflow != "ci.yml" || got.Status != "success" || len(got.Jobs) != 2 || got.Jobs[0].Status != "success" || got.Jobs[1].Status != "failure" || got.Jobs[0].Attempt != 2 {
				t.Fatalf("normalized run: %s", wire)
			}
		})
	}
}
