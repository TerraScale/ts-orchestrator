package releasepush

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/appregistry"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

const appReleaseView = "app-release"

type AppReleaseObservation struct {
	Nonce             string                   `json:"nonce"`
	Region            string                   `json:"region"`
	Service           string                   `json:"service"`
	Configured        []string                 `json:"configured"`
	Release           *swarmruntime.Deployment `json:"release,omitempty"`
	Placement         *Placement               `json:"placement,omitempty"`
	Declared          bool                     `json:"declared"`
	ServingGeneration int64                    `json:"serving_generation,omitempty"`
	BakeGeneration    int64                    `json:"bake_generation,omitempty"`
	PassedAt          time.Time                `json:"passed_at,omitzero"`
}

func (h *Handler) observeAppRelease(w http.ResponseWriter, r *http.Request) {
	service, nonce := r.URL.Query().Get("service"), r.URL.Query().Get("nonce")
	claims, err := h.Verifier.Verify(r.Context(), strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if err != nil || !slices.Contains(appServices[claims.JobWorkflowRef], service) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !hex64.MatchString(nonce) {
		http.Error(w, "invalid observation nonce", http.StatusBadRequest)
		return
	}
	if h.AppRelease == nil {
		http.Error(w, "signed app observation unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	proof, err := h.AppRelease(ctx, service, nonce)
	if err != nil || proof.Service != service || proof.Nonce != nonce || proof.Region == "" {
		http.Error(w, "signed app observation unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(proof)
}

type appWait struct {
	service    string
	release    swarmruntime.Deployment
	configured []string
	required   []string
	output     io.Writer
}

func WaitSignedApp(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("release wait-signed", flag.ContinueOnError)
	flags.SetOutput(output)
	service := flags.String("service", "", "service")
	image := flags.String("image", "", "selected immutable image")
	revision := flags.String("revision", os.Getenv("GITHUB_SHA"), "signed image commit")
	run := flags.String("run-id", os.Getenv("GITHUB_RUN_ID"), "signed selection run")
	attempt := flags.String("run-attempt", os.Getenv("GITHUB_RUN_ATTEMPT"), "signed selection attempt")
	regionsFile := flags.String("regions", "deploy/m1/regions.json", "configured regions")
	scope := flags.String("scope", "", "explicit authorized regions, separated by commas")
	if err := flags.Parse(args); err != nil {
		return err
	}
	target := slices.IndexFunc(appregistry.Targets, func(t appregistry.Target) bool { return t.Service == *service })
	selectionAttempt, err := strconv.ParseUint(*attempt, 10, 64)
	if target < 0 || err != nil || selectionAttempt == 0 || flags.NArg() != 0 || !swarmruntime.DeploymentImageBelongsToService(*service, *image) {
		return errors.New("usage: ts-orch release wait-signed --service NAME --image IMAGE [--revision SHA --run-id ID --run-attempt N] [--regions FILE] [--scope gru]")
	}
	workflow := appregistry.Targets[target].Workflow
	repository, _, _ := strings.Cut(workflow, "/.github/workflows/")
	w := appWait{service: *service, output: output, release: swarmruntime.Deployment{Repository: repository, Workflow: workflow, Image: *image, Revision: *revision, RunID: *run, RunAttempt: selectionAttempt}}
	if err := w.release.Validate(); err != nil {
		return err
	}
	regions, err := LoadRegions(*regionsFile)
	if err != nil {
		return err
	}
	for _, region := range regions {
		w.configured = append(w.configured, region.Region)
	}
	w.configured, err = normalizeRegions(w.configured, w.configured)
	if err != nil {
		return err
	}
	w.required = w.configured
	if *scope != "" {
		w.required, err = normalizeRegions(strings.Split(*scope, ","), w.configured)
		if err != nil {
			return err
		}
	}
	return w.wait(ctx)
}

func normalizeRegions(regions, configured []string) ([]string, error) {
	names := slices.Clone(regions)
	slices.Sort(names)
	for i, name := range names {
		if _, known := catalog.LookupName(name); !known || !slices.Contains(configured, name) || i > 0 && names[i-1] == name {
			return nil, fmt.Errorf("invalid or duplicate target region %q", name)
		}
	}
	return names, nil
}

type appWaitResult struct {
	State      string               `json:"state"`
	Service    string               `json:"service"`
	Image      string               `json:"image"`
	Revision   string               `json:"revision"`
	RunID      string               `json:"run_id"`
	RunAttempt uint64               `json:"run_attempt"`
	Generation int64                `json:"generation"`
	Regions    []string             `json:"regions"`
	GRUReady   bool                 `json:"gru_ready"`
	Passed     map[string]time.Time `json:"passed_at"`
}

func (w appWait) wait(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, HandlerWait)
	defer cancel()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	encoder := json.NewEncoder(w.output)
	var reportedGRU int64
	for {
		observations, err := w.sample(ctx)
		if err != nil {
			return err
		}
		result, err := w.evaluate(observations)
		if err != nil {
			return err
		}
		if result.GRUReady && result.Generation != reportedGRU {
			reportedGRU = result.Generation
			result.State = "gru_ready"
			if err := encoder.Encode(result); err != nil {
				return err
			}
		}
		if len(result.Passed) == len(w.required) {
			result.State = "done"
			return encoder.Encode(result)
		}
		var pending []string
		for _, region := range w.required {
			if _, passed := result.Passed[region]; !passed {
				pending = append(pending, region)
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("signed rollout proof pending in %s: %w", strings.Join(pending, ", "), ctx.Err())
		case <-tick.C:
		}
	}
}

func (w appWait) sample(ctx context.Context) ([]AppReleaseObservation, error) {
	token, err := MintToken(ctx)
	if err != nil {
		return nil, err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	challenge := hex.EncodeToString(nonce[:])
	query := url.Values{"view": {appReleaseView}, "service": {w.service}, "nonce": {challenge}}
	observed, failed := make([]AppReleaseObservation, len(w.required)), make([]error, len(w.required))
	var group sync.WaitGroup
	for i, region := range w.required {
		group.Go(func() {
			status, err := getObservation(ctx, Region{Region: region}, "", token, query, &observed[i])
			switch status {
			case 0, http.StatusServiceUnavailable:
				observed[i] = AppReleaseObservation{}
			case http.StatusOK:
				value := observed[i]
				if err != nil || value.Service != w.service || value.Region != region || value.Nonce != challenge {
					failed[i] = fmt.Errorf("%s returned no fresh signed app observation", region)
				}
			default:
				failed[i] = fmt.Errorf("%s: signed app observation HTTP %d", region, status)
			}
		})
	}
	group.Wait()
	return observed, errors.Join(failed...)
}

func (w appWait) evaluate(observations []AppReleaseObservation) (appWaitResult, error) {
	result := appWaitResult{Service: w.service, Image: w.release.Image, Revision: w.release.Revision, RunID: w.release.RunID, RunAttempt: w.release.RunAttempt, Regions: w.required, Passed: map[string]time.Time{}}
	for _, observed := range observations {
		if observed.Release == nil || observed.Placement == nil || observed.Placement.RollbackOf != 0 || observed.Placement.Generation <= 0 {
			continue
		}
		release := *observed.Release
		if !appregistry.SameDigest(release.Image, w.release.Image) {
			continue
		}
		release.Image = w.release.Image
		if release != w.release {
			continue
		}
		configured, err := normalizeRegions(observed.Configured, observed.Configured)
		if err != nil || !slices.Equal(configured, w.configured) {
			return result, fmt.Errorf("%s reports configured targets %v, expected %v", observed.Region, observed.Configured, w.configured)
		}
		placement := w.configured
		if len(observed.Placement.Regions) != 0 {
			var err error
			placement, err = normalizeRegions(observed.Placement.Regions, w.configured)
			if err != nil {
				return result, fmt.Errorf("%s reported invalid placement: %w", observed.Region, err)
			}
		}
		var undeclared []string
		for _, required := range w.required {
			if !slices.Contains(placement, required) || required == observed.Region && !observed.Declared {
				undeclared = append(undeclared, required)
			}
		}
		if len(undeclared) != 0 {
			return result, fmt.Errorf("required regions %s undeclared for %s in signed generation %d", strings.Join(undeclared, ", "), w.service, observed.Placement.Generation)
		}
		if !slices.Equal(placement, w.required) {
			return result, fmt.Errorf("requested scope %v differs from authorized placement %v", w.required, placement)
		}
		generation := observed.Placement.Generation
		if result.Generation != 0 && result.Generation != generation {
			return result, fmt.Errorf("%s reports conflicting signed generation %d, already observed %d", observed.Region, generation, result.Generation)
		}
		result.Generation = generation
		if observed.ServingGeneration == generation && observed.BakeGeneration == generation && !observed.PassedAt.IsZero() {
			result.Passed[observed.Region] = observed.PassedAt
		}
	}
	_, result.GRUReady = result.Passed["gru"]
	return result, nil
}
