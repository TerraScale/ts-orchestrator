package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/fleet"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

type request struct {
	Region      string                   `json:"region"`
	Compartment string                   `json:"compartment"`
	Instances   []string                 `json:"instances"`
	Prefix      string                   `json:"prefix"`
	Operation   string                   `json:"operation"`
	Name        string                   `json:"name"`
	Tenant      string                   `json:"tenant"`
	Seconds     int                      `json:"seconds"`
	Node        string                   `json:"node"`
	Spec        swarmruntime.ServiceSpec `json:"spec"`
}

type node struct {
	ID, Instance, Host, State string
}

type task struct {
	ID, Node, State string
	Exit            int32
	OOM             bool
}

type service struct {
	Name     string
	Replicas uint64
	Tasks    []task
}

type snapshot struct {
	Nodes      []node
	Services   []service
	Neighbours []task
	Orphans    int
}

func attest(ctx context.Context, r request) error {
	if !slices.Contains(strings.Split(r.Region, "-"), "staging") || !strings.HasPrefix(r.Prefix, "abuse-") || len(r.Prefix) > 40 || strings.ContainsAny(r.Prefix, "/.\\ \n") || r.Compartment == "" {
		return errors.New("staging scope required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://169.254.169.254/opc/v2/instance/", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer Oracle")
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return errors.New("OCI metadata unavailable")
	}
	defer response.Body.Close()
	var metadata struct {
		ID          string `json:"id"`
		Compartment string `json:"compartmentId"`
	}
	if response.StatusCode != 200 || json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&metadata) != nil || metadata.Compartment != r.Compartment || !slices.Contains(r.Instances, metadata.ID) {
		return errors.New("host is outside OCI-attested staging scope")
	}
	return nil
}

func observe(ctx context.Context, client api.ControlClient, r request, mutate bool) (snapshot, error) {
	result := snapshot{}
	nodes, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return result, err
	}
	ready := 0
	for _, n := range nodes.Nodes {
		labels := n.Spec.Annotations.Labels
		instance := labels[swarmruntime.LabelInstanceID]
		if !strings.EqualFold(labels[swarmruntime.LabelRegion], r.Region) || instance == "" || mutate && !slices.Contains(r.Instances, instance) {
			return result, errors.New("cluster member outside staging authority")
		}
		if n.Status.State == api.NodeStatus_READY {
			ready++
		}
		host := n.Spec.Annotations.Name
		if n.Description != nil {
			host = n.Description.Hostname
		}
		result.Nodes = append(result.Nodes, node{n.ID, instance, host, n.Status.State.String()})
	}
	if ready > 3 || len(nodes.Nodes) == 0 {
		return result, errors.New("staging node bound violated")
	}
	services, err := client.ListServices(ctx, &api.ListServicesRequest{})
	if err != nil {
		return result, err
	}
	for _, s := range services.Services {
		if !strings.HasPrefix(s.Spec.Annotations.Name, r.Prefix+"-") {
			tasks, err := client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{s.ID}}})
			if err != nil {
				return result, err
			}
			for _, t := range tasks.Tasks {
				if t.Status.State == api.TaskStateRunning {
					result.Neighbours = append(result.Neighbours, task{ID: t.ID, Node: t.NodeID, State: t.Status.State.String()})
				}
			}
			continue
		}
		if s.Spec.Annotations.Labels["terrascale.abuse-run"] != r.Prefix {
			container := s.Spec.Task.GetContainer()
			if container == nil || !slices.ContainsFunc(container.Env, func(value string) bool { return strings.HasPrefix(value, "ABUSE_TENANT="+r.Prefix+"-") }) {
				return result, errors.New("abuse namespace belongs to another owner")
			}
		}
		replicated := s.Spec.GetReplicated()
		if replicated == nil {
			return result, errors.New("abuse service must be replicated")
		}
		row := service{Name: s.Spec.Annotations.Name, Replicas: replicated.Replicas}
		tasks, err := client.ListTasks(ctx, &api.ListTasksRequest{Filters: &api.ListTasksRequest_Filters{ServiceIDs: []string{s.ID}}})
		if err != nil {
			return result, err
		}
		for _, t := range tasks.Tasks {
			exit := int32(-1)
			if status := t.Status.GetContainer(); status != nil {
				exit = status.ExitCode
			}
			row.Tasks = append(row.Tasks, task{t.ID, t.NodeID, t.Status.State.String(), exit, strings.Contains(strings.ToLower(t.Status.Err), "oom")})
		}
		result.Services = append(result.Services, row)
	}
	allTasks, err := client.ListTasks(ctx, &api.ListTasksRequest{})
	if err != nil {
		return result, err
	}
	for _, t := range allTasks.Tasks {
		if strings.HasPrefix(t.ServiceAnnotations.Name, r.Prefix+"-") && t.Status.State <= api.TaskStateRunning && !slices.ContainsFunc(services.Services, func(s *api.Service) bool { return s.ID == t.ServiceID }) {
			result.Orphans++
		}
	}
	return result, nil
}

func run() error {
	var r request
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&r); err != nil {
		return errors.New("invalid abuse control request")
	}
	if r.Seconds <= 0 || r.Seconds > 7200 {
		return errors.New("bounded observation required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(r.Seconds)*time.Second)
	defer cancel()
	if err := attest(ctx, r); err != nil {
		return err
	}
	client, conn, err := swarmruntime.DialControl("/var/lib/ts-orch")
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := observe(ctx, client, r, r.Operation != "watch" && r.Operation != "snapshot"); err != nil {
		return err
	}
	switch r.Operation {
	case "recover":
		document, err := fleet.Load()
		if err != nil {
			return err
		}
		index := slices.IndexFunc(document.Regions, func(region fleet.Region) bool { return region.Label == r.Region })
		if index < 0 || document.Regions[index].CompartmentID != r.Compartment || document.Regions[index].Nodes.Max > 3 {
			return errors.New("compute recovery outside staging authority")
		}
		if err := fleet.Apply(ctx, []string{r.Region, "compute"}, io.Discard); err != nil {
			return err
		}
	case "apply":
		if !strings.HasPrefix(r.Spec.Name, r.Prefix+"-") || len(r.Spec.Regions) != 1 || r.Spec.Regions[0] != r.Region || r.Tenant == "" || !strings.HasPrefix(r.Tenant, r.Prefix) {
			return errors.New("service outside abuse tenant")
		}
		r.Spec.Dependencies = new([]string{})
		created, err := swarmruntime.ApplyServiceSpec(ctx, client, r.Spec)
		if err != nil {
			return err
		}
		spec := created.Spec.Copy()
		spec.Annotations.Labels["terrascale.abuse-run"] = r.Prefix
		spec.Annotations.Labels["terrascale.tenant"] = r.Tenant
		spec.Annotations.Labels[swarmruntime.LabelEnvironment] = r.Prefix
		if spec.Task.Placement == nil {
			spec.Task.Placement = &api.Placement{}
		}
		if r.Spec.Replicas > 1 {
			spec.Task.Placement.MaxReplicas = 1
		}
		if r.Node != "" {
			state, err := observe(ctx, client, r, true)
			if err != nil || !slices.ContainsFunc(state.Nodes, func(n node) bool { return n.ID == r.Node }) {
				return errors.New("placement outside staging cluster")
			}
			spec.Task.Placement.Constraints = append(spec.Task.Placement.Constraints, "node.id=="+r.Node)
		}
		if _, err := client.UpdateService(ctx, &api.UpdateServiceRequest{ServiceID: created.ID, ServiceVersion: &created.Meta.Version, Spec: spec}); err != nil {
			return err
		}
	case "remove":
		if !strings.HasPrefix(r.Name, r.Prefix+"-") {
			return errors.New("removal outside abuse tenant")
		}
		if err := swarmruntime.RemoveServiceSpec(ctx, client, r.Name); err != nil {
			return err
		}
	case "watch":
		stream, err := api.NewWatchClient(conn).Watch(ctx, &api.WatchRequest{Entries: []*api.WatchRequest_WatchEntry{{Kind: "task", Action: 7}, {Kind: "service", Action: 7}, {Kind: "node", Action: 7}}})
		if err != nil {
			return err
		}
		if _, err := stream.Recv(); err != nil {
			return err
		}
		for {
			state, err := observe(ctx, client, r, false)
			if err != nil {
				return err
			}
			if err := json.NewEncoder(os.Stdout).Encode(state); err != nil {
				return err
			}
			if _, err := stream.Recv(); err != nil {
				return err
			}
		}
	case "snapshot":
	default:
		return errors.New("unknown abuse operation")
	}
	state, err := observe(ctx, client, r, false)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(state)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "abuse control failed:", err)
		os.Exit(1)
	}
}
