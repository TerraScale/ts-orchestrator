// Package geodns plans the OCI DNS traffic-management steering policy that
// sends each user to the nearest healthy region edge. It only plans: the
// field names match the OCI DNS and Health Checks REST bodies
// (CreateSteeringPolicy, CreateHttpMonitor, CreateSteeringPolicyAttachment)
// so the live apply can send them unchanged.
package geodns

import (
	"cmp"
	"math"
	"slices"
	"strings"
)

// Zone is the subzone delegated from Cloudflare to OCI DNS.
const Zone = "edge.terrascale.tech"

// Hosts are the public hostnames every region serves.
var Hosts = []string{"api.terrascale.tech", "auth.terrascale.tech", "dash.terrascale.tech"}

// Region is one serving region edge.
type Region struct {
	Name                string
	IP                  string
	Latitude, Longitude float64
}

// area is a GeoNames geoKey with a point that stands for where its users are.
type area struct {
	Name     string
	GeoKey   string
	Lat, Lng float64
}

// areas lists countries before continents: the first matching case wins, so
// South and West Asia are not sent the East Asia way.
var areas = []area{
	{"India", "1269750", 19.08, 72.88},
	{"United Arab Emirates", "290557", 25.20, 55.27},
	{"Saudi Arabia", "102358", 24.71, 46.68},
	{"Israel", "294640", 31.77, 35.21},
	{"Turkey", "298795", 41.01, 28.98},
	{"Africa", "6255146", 2.0, 20.0},
	{"Asia", "6255147", 35.68, 139.69},
	{"Europe", "6255148", 50.0, 10.0},
	{"North America", "6255149", 40.0, -95.0},
	{"South America", "6255150", -15.0, -55.0},
	{"Oceania", "6255151", -33.87, 151.21},
}

// Answer is dns.SteeringPolicyAnswer.
type Answer struct {
	Name  string `json:"name"`
	Rtype string `json:"rtype"`
	Rdata string `json:"rdata"`
	Pool  string `json:"pool"`
}

// AnswerData is dns.SteeringPolicy{Filter,Priority}AnswerData.
type AnswerData struct {
	AnswerCondition string `json:"answerCondition"`
	ShouldKeep      *bool  `json:"shouldKeep,omitempty"`
	Value           *int   `json:"value,omitempty"`
}

// Case is one dns.SteeringPolicy*RuleCase.
type Case struct {
	CaseCondition string       `json:"caseCondition"`
	AnswerData    []AnswerData `json:"answerData"`
}

// Rule is one dns.SteeringPolicyRule.
type Rule struct {
	RuleType          string       `json:"ruleType"`
	Description       string       `json:"description,omitempty"`
	Cases             []Case       `json:"cases,omitempty"`
	DefaultAnswerData []AnswerData `json:"defaultAnswerData,omitempty"`
	DefaultCount      *int         `json:"defaultCount,omitempty"`
}

// Policy is dns.CreateSteeringPolicyDetails.
type Policy struct {
	CompartmentID        string   `json:"compartmentId"`
	DisplayName          string   `json:"displayName"`
	Template             string   `json:"template"`
	TTL                  int      `json:"ttl"`
	HealthCheckMonitorID string   `json:"healthCheckMonitorId"`
	Answers              []Answer `json:"answers"`
	Rules                []Rule   `json:"rules"`
}

// Monitor is healthchecks.CreateHttpMonitorDetails.
type Monitor struct {
	CompartmentID     string            `json:"compartmentId"`
	DisplayName       string            `json:"displayName"`
	Targets           []string          `json:"targets"`
	Protocol          string            `json:"protocol"`
	Port              int               `json:"port"`
	Method            string            `json:"method"`
	Path              string            `json:"path"`
	Headers           map[string]string `json:"headers"`
	IntervalInSeconds int               `json:"intervalInSeconds"`
	TimeoutInSeconds  int               `json:"timeoutInSeconds"`
}

// Attachment is dns.CreateSteeringPolicyAttachmentDetails.
type Attachment struct {
	SteeringPolicyID string `json:"steeringPolicyId"`
	ZoneID           string `json:"zoneId"`
	DomainName       string `json:"domainName"`
	DisplayName      string `json:"displayName"`
}

// HostPlan is everything one public hostname needs.
type HostPlan struct {
	Host       string     `json:"host"`
	Monitor    Monitor    `json:"monitor"`
	Policy     Policy     `json:"policy"`
	Attachment Attachment `json:"attachment"`
	// Nearest maps each geo area to its first-choice region, for the table.
	Nearest map[string]string `json:"-"`
}

// Placeholders stand for IDs that exist only once the live apply creates them.
const compartment = "<ts-orch compartment OCID>"

// Build plans one steering policy per host over every region; regions keep
// their order, which is also the order of the no-geo-match fallback.
func Build(regions []Region, hosts []string) []HostPlan {
	label := func(host string) string { return strings.SplitN(host, ".", 2)[0] }
	answers := make([]Answer, 0, len(regions))
	targets := make([]string, 0, len(regions))
	for _, r := range regions {
		answers = append(answers, Answer{Name: r.Name, Rtype: "A", Rdata: r.IP, Pool: r.Name})
		targets = append(targets, r.IP)
	}
	keep, one := true, 1
	var cases []Case
	nearest := map[string]string{}
	for _, a := range areas {
		ranked := slices.Clone(regions)
		slices.SortStableFunc(ranked, func(x, y Region) int {
			return cmp.Compare(km(a.Lat, a.Lng, x.Latitude, x.Longitude), km(a.Lat, a.Lng, y.Latitude, y.Longitude))
		})
		cases = append(cases, Case{CaseCondition: "query.client.geoKey in (geoKey '" + a.GeoKey + "')", AnswerData: priorities(ranked)})
		nearest[a.Name] = ranked[0].Name
	}
	plans := make([]HostPlan, 0, len(hosts))
	for _, host := range hosts {
		name := "ts-edge-" + label(host)
		plans = append(plans, HostPlan{
			Host: host,
			Monitor: Monitor{
				CompartmentID: compartment, DisplayName: name, Targets: targets,
				// :80 answers /readyz unredirected: a probe of a bare IP has no SNI for HTTPS.
				Protocol: "HTTP", Port: 80, Method: "GET", Path: "/readyz",
				Headers:           map[string]string{"Host": host},
				IntervalInSeconds: 30, TimeoutInSeconds: 10,
			},
			Policy: Policy{
				CompartmentID: compartment, DisplayName: name, Template: "ROUTE_BY_GEO", TTL: 30,
				HealthCheckMonitorID: "<monitor " + name + " OCID>",
				Answers:              answers,
				Rules: []Rule{
					{RuleType: "FILTER", Description: "drop disabled answers", DefaultAnswerData: []AnswerData{{AnswerCondition: "answer.isDisabled != true", ShouldKeep: &keep}}},
					{RuleType: "HEALTH", Description: "drop regions failing /readyz"},
					{RuleType: "PRIORITY", Description: "nearest region first, then next nearest", Cases: cases, DefaultAnswerData: priorities(regions)},
					{RuleType: "LIMIT", Description: "answer with one region", DefaultCount: &one},
				},
			},
			Attachment: Attachment{
				SteeringPolicyID: "<policy " + name + " OCID>", ZoneID: "<zone " + Zone + " OCID>",
				DomainName: label(host) + "." + Zone, DisplayName: name,
			},
			Nearest: nearest,
		})
	}
	return plans
}

// priorities ranks regions 1..n in the given order.
func priorities(ranked []Region) []AnswerData {
	data := make([]AnswerData, len(ranked))
	for i, r := range ranked {
		value := i + 1
		data[i] = AnswerData{AnswerCondition: "answer.pool == '" + r.Name + "'", Value: &value}
	}
	return data
}

// km is the great-circle distance between two points.
func km(lat1, lng1, lat2, lng2 float64) float64 {
	rad := math.Pi / 180
	dLat, dLng := (lat2-lat1)*rad, (lng2-lng1)*rad
	h := math.Pow(math.Sin(dLat/2), 2) + math.Cos(lat1*rad)*math.Cos(lat2*rad)*math.Pow(math.Sin(dLng/2), 2)
	return 2 * 6371 * math.Asin(math.Sqrt(h))
}
