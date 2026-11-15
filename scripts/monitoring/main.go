package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	goparser "go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
	"go.yaml.in/yaml/v3"
)

type rule struct {
	Alert         string            `yaml:"alert,omitempty" json:"alert,omitempty"`
	Record        string            `yaml:"record,omitempty" json:"record,omitempty"`
	Expr          string            `yaml:"expr" json:"expr"`
	For           string            `yaml:"for,omitempty" json:"for,omitempty"`
	KeepFiringFor string            `yaml:"keep_firing_for,omitempty" json:"keep_firing_for,omitempty"`
	Labels        map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
	Annotations   map[string]string `yaml:"annotations,omitempty" json:"annotations,omitempty"`
}

type group struct {
	Name     string `yaml:"name" json:"name"`
	Interval string `yaml:"interval,omitempty" json:"interval,omitempty"`
	Rules    []rule `yaml:"rules" json:"rules"`
}

type rules struct {
	Groups []group `yaml:"groups" json:"groups"`
}

type inventory struct {
	Hosts    []string
	Regions  []string
	Monitors []string
}

var fleetAlerts = []string{"ServiceReadinessFailed", "ProductionJourneyFailed", "ProductionJourneyTelemetryMissing", "CertificateExpirySoon", "AlertDeliveryHeartbeat", "AlertDeliveryProbeStale", "AlertDeliveryProbeMissing", "AlertmanagerClusterDegraded"}

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Fprintln(os.Stderr, "usage: go run -C scripts/monitoring . <output-directory> <source-directory>")
		os.Exit(2)
	}
	if len(os.Args) == 3 {
		if err := os.Chdir(os.Args[2]); err != nil {
			panic(err)
		}
	}
	if err := render(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func render(output string) error {
	inv, err := readInventory()
	if err != nil {
		return err
	}
	catalog, err := metricCatalog()
	if err != nil {
		return err
	}
	var source rules
	for _, name := range []string{"deploy/observability/slo-rules.yml", "deploy/observability/production/operational-rules.yml", "deploy/observability/production/host-storage-rules.yml"} {
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		var part rules
		decoder := yaml.NewDecoder(strings.NewReader(string(data)))
		decoder.KnownFields(true)
		if err := decoder.Decode(&part); err != nil {
			return err
		}
		source.Groups = append(source.Groups, part.Groups...)
	}
	for _, g := range source.Groups {
		for _, r := range g.Rules {
			if r.Record != "" {
				catalog[r.Record] = true
			}
		}
	}
	for _, g := range source.Groups {
		for _, r := range g.Rules {
			if _, pinned := r.Labels["region"]; pinned {
				return errors.New("source rules must not pin a region label")
			}
			if _, err := regionalExpression(r.Expr, inv.Regions[0], catalog); err != nil {
				return fmt.Errorf("%s%s: %w", r.Alert, r.Record, err)
			}
		}
	}
	for _, monitor := range inv.Monitors {
		var generated rules
		for _, g := range source.Groups {
			target := group{Name: g.Name + "-global", Interval: g.Interval}
			for _, r := range g.Rules {
				fleet := slices.Contains(fleetAlerts, r.Alert)
				if g.Name != "service-slo" && !fleet || r.Alert == "ServiceSLOTelemetryMissing" || r.Record == "terrascale_slo_requests_total" {
					continue
				}
				if g.Name == "service-slo" {
					expr, err := parser.NewParser(parser.Options{}).ParseExpr(r.Expr)
					if err != nil {
						return err
					}
					parser.Inspect(expr, func(node parser.Node, _ []parser.Node) error {
						if selector, ok := node.(*parser.VectorSelector); ok && strings.HasPrefix(selector.Name, "slo:") {
							selector.LabelMatchers = append(selector.LabelMatchers, labels.MustNewMatcher(labels.MatchEqual, "region", "global"))
						}
						return nil
					})
					r.Expr = expr.String()
					if r.Alert != "" {
						r.Alert += "Global"
					}
				}
				r.Labels = copyLabels(r.Labels)
				r.Labels["region"] = "global"
				target.Rules = append(target.Rules, r)
			}
			if len(target.Rules) > 0 {
				generated.Groups = append(generated.Groups, target)
			}
		}
		for _, region := range inv.Regions {
			for _, g := range source.Groups {
				target := group{Name: g.Name + "-" + region, Interval: g.Interval}
				for _, r := range g.Rules {
					if slices.Contains(fleetAlerts, r.Alert) {
						continue
					}
					if _, pinned := r.Labels["region"]; pinned {
						return errors.New("source rules must not pin a region label")
					}
					expr, err := regionalExpression(r.Expr, region, catalog)
					if err != nil {
						return fmt.Errorf("%s%s: %w", r.Alert, r.Record, err)
					}
					r.Expr = expr
					r.Labels = copyLabels(r.Labels)
					r.Labels["region"] = region
					target.Rules = append(target.Rules, r)
				}
				generated.Groups = append(generated.Groups, target)
			}
			generated.Groups = append(generated.Groups, coverageRules(inv, region))
		}
		dir := filepath.Join(output, monitor)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(dir, "rules.yml"), generated); err != nil {
			return err
		}
		unit, err := os.ReadFile("deploy/observability/production/ts-alertmanager.service")
		if err != nil {
			return err
		}
		var peers []string
		for _, peer := range inv.Monitors {
			if peer != monitor {
				peers = append(peers, "--cluster.peer="+peer+".nb.ts.internal:9095")
			}
		}
		unit = []byte(strings.ReplaceAll(string(unit), "@peers@", strings.Join(peers, " ")))
		if err := os.WriteFile(filepath.Join(dir, "ts-alertmanager.service"), unit, 0644); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(dir, "email-budget.json"), map[string]int{"hourly": 12 / len(inv.Monitors), "daily": 288 / len(inv.Monitors)}); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(dir, "prometheus.yml"), prometheusConfig(inv, monitor)); err != nil {
			return err
		}
	}
	fmt.Printf("monitoring: rendered %d independent backends, %d regions and %d hosts; every selector names an exported metric\n", len(inv.Monitors), len(inv.Regions), len(inv.Hosts))
	return nil
}

func readInventory() (inventory, error) {
	data, err := os.ReadFile("deploy/observability/production/hosts.txt")
	if err != nil {
		return inventory{}, err
	}
	inv := inventory{Hosts: strings.Fields(string(data))}
	seen := map[string]bool{}
	valid := regexp.MustCompile(`^ts-([a-z]{3})-[1-9][0-9]*$`)
	for _, host := range inv.Hosts {
		match := valid.FindStringSubmatch(host)
		if match == nil || seen[host] {
			return inv, fmt.Errorf("invalid monitoring host: %s", host)
		}
		seen[host] = true
		if !slices.Contains(inv.Regions, match[1]) {
			inv.Regions = append(inv.Regions, match[1])
			inv.Monitors = append(inv.Monitors, host)
		}
	}
	if len(inv.Regions) < 2 {
		return inv, errors.New("monitoring requires at least two regions")
	}
	return inv, nil
}

func copyLabels(source map[string]string) map[string]string {
	target := map[string]string{}
	for key, value := range source {
		target[key] = value
	}
	return target
}

func regionalExpression(text, region string, catalog map[string]bool) (string, error) {
	expr, err := parser.NewParser(parser.Options{}).ParseExpr(text)
	if err != nil {
		return "", err
	}
	var invalid error
	parser.Inspect(expr, func(node parser.Node, _ []parser.Node) error {
		switch n := node.(type) {
		case *parser.VectorSelector:
			if !catalog[n.Name] {
				invalid = fmt.Errorf("metric has no exporter: %s", n.Name)
				return invalid
			}
			for _, m := range n.LabelMatchers {
				if m.Name == "region" {
					invalid = errors.New("source rules must not pin a region")
					return invalid
				}
			}
			n.LabelMatchers = append(n.LabelMatchers, labels.MustNewMatcher(labels.MatchEqual, "region", region))
		case *parser.AggregateExpr:
			if !n.Without && !slices.Contains(n.Grouping, "region") {
				n.Grouping = append(n.Grouping, "region")
			}
		case *parser.BinaryExpr:
			if n.VectorMatching != nil && n.VectorMatching.On && !slices.Contains(n.VectorMatching.MatchingLabels, "region") {
				n.VectorMatching.MatchingLabels = append(n.VectorMatching.MatchingLabels, "region")
			}
		}
		return nil
	})
	if invalid != nil {
		return "", invalid
	}
	return expr.String(), nil
}

func metricCatalog() (map[string]bool, error) {
	catalog := map[string]bool{"up": true}
	data, err := os.ReadFile("deploy/observability/production/metric-catalog.txt")
	if err != nil {
		return nil, err
	}
	for _, metric := range strings.Fields(string(data)) {
		catalog[metric] = true
	}
	metricName := regexp.MustCompile(`(?:ts_(?:orch|host|edge)_|terrascale_)[a-zA-Z0-9_:]+`)
	err = filepath.WalkDir("internal", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		source, err := goparser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(source, func(node ast.Node) bool {
			if binary, ok := node.(*ast.BinaryExpr); ok && binary.Op == token.ADD {
				prefix, ok := binary.X.(*ast.SelectorExpr)
				suffix, literal := binary.Y.(*ast.BasicLit)
				if ok && prefix.Sel.Name == "MetricPrefix" && literal && suffix.Kind == token.STRING {
					value, err := strconv.Unquote(suffix.Value)
					if err == nil {
						catalog["ts_orch_"+value] = true
					}
				}
			}
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil {
				return true
			}
			for _, metric := range metricName.FindAllString(value, -1) {
				catalog[metric] = true
			}
			return true
		})
		return nil
	})
	return catalog, err
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0644)
}

func coverageRules(inv inventory, region string) group {
	var hosts []string
	for _, host := range inv.Hosts {
		if strings.Split(host, "-")[1] == region {
			hosts = append(hosts, host)
		}
	}
	absent := func(metric string) string {
		var terms []string
		for _, host := range hosts {
			terms = append(terms, fmt.Sprintf("absent(%s{job=\"host-storage\",host=%q,region=%q})", metric, host, region))
		}
		return strings.Join(terms, " or ")
	}
	return group{Name: "coverage-" + region, Rules: []rule{
		{Alert: "HostServiceTaskInventoryMissing", Expr: absent("ts_host_service_tasks_expected"), For: "15m", Labels: map[string]string{"region": region, "severity": "critical"}, Annotations: map[string]string{"summary": "Service task inventory is absent on {{ $labels.host }}"}},
		{Alert: "ExpectedNodeAbsent", Expr: fmt.Sprintf("(up{job=\"host-storage\",region=%q} == 0) or ", region) + absent("up"), For: "5m", Labels: map[string]string{"region": region, "severity": "critical"}, Annotations: map[string]string{"summary": "Expected node {{ $labels.host }} has no host-storage heartbeat ({{ $labels.region }})"}},
		{Alert: "MonitoringBackendDown", Expr: fmt.Sprintf("up{job=~\"monitoring-prometheus|monitoring-alertmanager|service-readiness\",region=%q} == 0", region), For: "2m", Labels: map[string]string{"region": region, "severity": "critical"}, Annotations: map[string]string{"summary": "A regional monitoring backend is unavailable"}},
	}}
}

func prometheusConfig(inv inventory, monitor string) map[string]any {
	var discovery, hosts, controllers, backends []map[string]any
	var alertmanagers []string
	for _, host := range inv.Hosts {
		region := strings.Split(host, "-")[1]
		discovery = append(discovery, map[string]any{"url": "http://" + host + ".nb.ts.internal:9108/services", "refresh_interval": "15s"})
		hosts = append(hosts, map[string]any{"targets": []string{host + ".nb.ts.internal:9108"}, "labels": map[string]string{"host": host, "region": region, "instance": host, "service": "host-storage"}})
		controllers = append(controllers, map[string]any{"targets": []string{host + ".nb.ts.internal:9108"}, "labels": map[string]string{"host": host, "region": region, "instance": host, "service": "orchestrator"}})
	}
	for _, host := range inv.Monitors {
		alertmanagers = append(alertmanagers, host+".nb.ts.internal:9093")
		backends = append(backends, map[string]any{"targets": []string{host + ".nb.ts.internal:9108"}, "labels": map[string]string{"host": host, "region": strings.Split(host, "-")[1], "instance": host}})
	}
	return map[string]any{
		"global":     map[string]any{"scrape_interval": "15s", "evaluation_interval": "15s", "external_labels": map[string]string{"monitor": monitor}},
		"rule_files": []string{"rules.yml"},
		"alerting":   map[string]any{"alert_relabel_configs": []map[string]any{{"action": "labeldrop", "regex": "monitor"}}, "alertmanagers": []map[string]any{{"static_configs": []map[string]any{{"targets": alertmanagers}}}}},
		"scrape_configs": []map[string]any{
			{"job_name": "application-slo", "http_sd_configs": discovery},
			{"job_name": "host-storage", "honor_labels": true, "sample_limit": 4096, "static_configs": hosts},
			{"job_name": "peer-topology", "metrics_path": "/orchestrator/metrics", "honor_labels": true, "scrape_interval": "5s", "static_configs": controllers},
			{"job_name": "terrabase-host-storage", "sample_limit": 48, "static_configs": hosts,
				"relabel_configs":        []map[string]any{{"source_labels": []string{"__address__"}, "regex": "(.*):9108", "target_label": "__address__", "replacement": "${1}:9091"}},
				"metric_relabel_configs": []map[string]any{{"source_labels": []string{"__name__"}, "regex": "terrabase_storage_(queued|running|admitted)", "action": "keep"}, {"regex": "__name__|host|region|service|instance|job", "action": "labelkeep"}}},
			{"job_name": "monitoring-prometheus", "metrics_path": "/monitoring/prometheus/metrics", "static_configs": backends},
			{"job_name": "monitoring-alertmanager", "metrics_path": "/monitoring/alertmanager/metrics", "static_configs": backends},
			{"job_name": "service-readiness", "metrics_path": "/monitoring/relay/metrics", "scrape_timeout": "10s", "static_configs": backends},
		},
	}
}
