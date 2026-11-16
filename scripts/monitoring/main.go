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
	"time"

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

var fleetAlerts = []string{"ServiceReadinessFailed", "ProductionJourneyFailed", "ProductionJourneyTelemetryMissing", "CertificateExpirySoon", "AlertDeliveryHeartbeat", "AlertDeliveryProbeStale", "AlertDeliveryProbeMissing", "AlertmanagerClusterDegraded", "AlertDeliveryEmailBudgetExhausted", "AlertDeliveryEmailBudgetUnavailable"}

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
	if err := checkNotificationTiming("deploy/observability/production/alertmanager.yml", len(inv.Monitors)); err != nil {
		return err
	}
	if err := checkFleetInstall(); err != nil {
		return err
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
		unit, err := fleetAlertmanagerUnit(inv.Monitors, monitor)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "ts-alertmanager.service"), unit, 0644); err != nil {
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

const alertmanagerPeerTimeout = 15 * time.Second

type notificationRoute struct {
	GroupInterval string              `yaml:"group_interval"`
	Routes        []notificationRoute `yaml:"routes"`
}

func checkNotificationTiming(path string, peers int) error {
	deadline, err := readNamedDuration("internal/alertdelivery/endpoints.go", "notificationDeadline")
	if err != nil {
		return err
	}
	if deadline >= alertmanagerPeerTimeout {
		return fmt.Errorf("notification deadline %s must be well under the %s peer timeout", deadline, alertmanagerPeerTimeout)
	}
	if err := checkLaneTimingRatio(deadline); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var config struct {
		Route notificationRoute `yaml:"route"`
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		return err
	}
	var walk func(notificationRoute, time.Duration) error
	walk = func(route notificationRoute, inherited time.Duration) error {
		interval := inherited
		if route.GroupInterval != "" {
			parsed, err := time.ParseDuration(route.GroupInterval)
			if err != nil {
				return err
			}
			interval = parsed
		}
		if interval <= time.Duration(peers)*alertmanagerPeerTimeout {
			return fmt.Errorf("alertmanager group_interval %s must exceed %d peers x %s peer timeout while the notification deadline is %s, or a peer resends a stale notification", interval, peers, alertmanagerPeerTimeout, deadline)
		}
		for _, child := range route.Routes {
			if err := walk(child, interval); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(config.Route, 5*time.Minute)
}

func fleetAlertmanagerUnit(monitors []string, monitor string) ([]byte, error) {
	unit, err := os.ReadFile("deploy/observability/production/ts-alertmanager.service")
	if err != nil {
		return nil, err
	}
	text := string(unit)
	const lone = "--cluster.listen-address="
	if !strings.Contains(text, lone) || strings.Contains(text, "EnvironmentFile") || strings.Contains(text, "MONITOR_ADDRESS") {
		return nil, errors.New("alertmanager unit must be the loopback form; the renderer adds the fleet address")
	}
	var peers []string
	for _, peer := range monitors {
		if peer != monitor {
			peers = append(peers, "--cluster.peer="+peer+".nb.ts.internal:9095")
		}
	}
	fleet := "--web.listen-address=${MONITOR_ADDRESS}:9093 --cluster.listen-address=${MONITOR_ADDRESS}:9095 --cluster.advertise-address=${MONITOR_ADDRESS}:9095 " + strings.Join(peers, " ")
	text = strings.Replace(text, lone, fleet, 1)
	text = strings.Replace(text, "[Service]\n", "[Service]\nEnvironmentFile=/etc/ts-monitoring/production/alertmanager.env\n", 1)
	return []byte(text), nil
}

func readNamedDuration(path, name string) (time.Duration, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	match := regexp.MustCompile(name + `\s*=\s*(\d+)\s*\*\s*time\.(Millisecond|Second|Minute)`).FindSubmatch(data)
	if match == nil {
		return 0, fmt.Errorf("%s missing from %s", name, path)
	}
	value, err := strconv.Atoi(string(match[1]))
	if err != nil {
		return 0, err
	}
	unit := map[string]time.Duration{"Millisecond": time.Millisecond, "Second": time.Second, "Minute": time.Minute}[string(match[2])]
	return time.Duration(value) * unit, nil
}

func checkLaneTimingRatio(deadline time.Duration) error {
	if _, err := os.Stat("test/e2e/m1/monitoring/fleet.py"); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	laneDeadline, err := readNamedDuration("test/e2e/m1/monitoring/_journey/endpoints.go", "notificationDeadline")
	if err != nil {
		return err
	}
	lane, err := os.ReadFile("test/e2e/m1/monitoring/fleet.py")
	if err != nil {
		return err
	}
	match := regexp.MustCompile(`--cluster\.peer-timeout=([0-9]+(?:\.[0-9]+)?)(ms|s)`).FindSubmatch(lane)
	if match == nil {
		return errors.New("monitoring lane must set --cluster.peer-timeout")
	}
	value, err := strconv.Atoi(string(match[1]))
	if err != nil {
		return err
	}
	lanePeer := time.Duration(value) * time.Millisecond
	if string(match[2]) == "s" {
		lanePeer = time.Duration(value) * time.Second
	}
	if laneDeadline.Milliseconds()*alertmanagerPeerTimeout.Milliseconds() != deadline.Milliseconds()*lanePeer.Milliseconds() {
		return fmt.Errorf("lane deadline %s and peer timeout %s must keep the production ratio %s/%s", laneDeadline, lanePeer, deadline, alertmanagerPeerTimeout)
	}
	return nil
}

func checkFleetInstall() error {
	script, err := os.ReadFile("deploy/observability/production/install.sh")
	if err != nil {
		return err
	}
	lines := strings.Split(string(script), "\n")
	writeLine := -1
	for i, line := range lines {
		if strings.Contains(line, "printf") && strings.Contains(line, "MONITOR_ADDRESS") && strings.Contains(line, "alertmanager.env") {
			writeLine = i
		}
	}
	if writeLine < 0 {
		return errors.New("fleet install does not write alertmanager.env")
	}
	window := strings.Join(lines[max(0, writeLine-8):writeLine+1], "\n")
	if !strings.Contains(window, "--local-fleet") {
		return errors.New("alertmanager.env is written outside the fleet install")
	}
	if !strings.Contains(string(script), "rm -f /etc/ts-monitoring/production/alertmanager.env") {
		return errors.New("a non-fleet install must remove alertmanager.env")
	}
	unit, err := os.ReadFile("deploy/observability/production/ts-alert-delivery-token.service")
	if err != nil {
		return err
	}
	text := string(unit)
	if !strings.Contains(text, "Type=oneshot") || !strings.Contains(text, "Restart=on-failure") || !strings.Contains(text, "ExecStart=/usr/local/bin/ts-orch alert-delivery copy-token") || strings.Contains(text, "prepare") {
		return errors.New("token unit must be a oneshot that restarts on failure and only copies the mesh token")
	}
	source, err := os.ReadFile("internal/alertdelivery/credentials.go")
	if err != nil {
		return err
	}
	body, err := functionBody(string(source), "copyMeshToken")
	if err != nil {
		return err
	}
	if strings.Contains(body, "ReadInstanceSecrets") {
		return errors.New("mesh token copy must not read Vault")
	}
	prepare, err := functionBody(string(source), "prepareCredentials")
	if err != nil {
		return err
	}
	if !strings.Contains(prepare, "ReadInstanceSecrets") || !strings.Contains(prepare, "writeMeshToken") {
		return errors.New("prepare must read Vault and copy the mesh token separately")
	}
	return nil
}

func functionBody(source, name string) (string, error) {
	start := strings.Index(source, "func "+name)
	if start < 0 {
		return "", fmt.Errorf("missing %s", name)
	}
	rest := source[start:]
	next := strings.Index(rest[1:], "\nfunc ")
	if next < 0 {
		return rest, nil
	}
	return rest[:next+1], nil
}

func metricCatalog() (map[string]bool, error) {
	catalog := map[string]bool{"up": true}
	data, err := os.ReadFile("deploy/observability/production/metric-catalog.txt")
	if err != nil {
		return nil, err
	}
	for _, metric := range strings.Fields(string(data)) {
		if strings.HasPrefix(metric, "terrabase_") || strings.HasPrefix(metric, "ts_auth_") {
			return nil, fmt.Errorf("metric-catalog.txt lists product metric %s; product names come only from product-metrics.txt", metric)
		}
		catalog[metric] = true
	}
	product, err := os.ReadFile("deploy/observability/production/product-metrics.txt")
	if err != nil {
		return nil, err
	}
	for _, metric := range strings.Fields(string(product)) {
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
