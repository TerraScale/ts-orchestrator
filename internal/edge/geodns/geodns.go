package geodns

import (
	"cmp"
	"math"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/ociresource"
)

type Region struct {
	Label, IP, APIName  string
	Continents          []string
	Latitude, Longitude float64
}

type Config struct {
	Zone, CompartmentID, Cell, Owner, HealthPath string
	Names                                        []string
	TTL                                          int
	Regions                                      []Region
}

func (c Config) key(kind, name string) ociresource.Key {
	return ociresource.Key{Region: c.Cell, Kind: kind, Name: name}
}

func (c Config) tags(kind, name string) map[string]string {
	return ociresource.Ownership{Owner: c.Owner}.Stamp(c.key(kind, name), 1, "").Freeform
}

func (c Config) owns(key ociresource.Key, tags map[string]string) bool {
	return ociresource.Ownership{Owner: c.Owner}.Owns(key, ociresource.Tags{Freeform: tags})
}

type Answer struct {
	Name  string `json:"name"`
	Rtype string `json:"rtype"`
	Rdata string `json:"rdata"`
	Pool  string `json:"pool"`
}

type AnswerData struct {
	AnswerCondition string `json:"answerCondition"`
	ShouldKeep      *bool  `json:"shouldKeep,omitempty"`
	Value           *int   `json:"value,omitempty"`
}

type Case struct {
	CaseCondition string       `json:"caseCondition,omitempty"`
	AnswerData    []AnswerData `json:"answerData"`
}

type Rule struct {
	RuleType          string       `json:"ruleType"`
	Cases             []Case       `json:"cases,omitempty"`
	DefaultAnswerData []AnswerData `json:"defaultAnswerData,omitempty"`
	DefaultCount      *int         `json:"defaultCount,omitempty"`
}

type Policy struct {
	CompartmentID        string            `json:"compartmentId"`
	DisplayName          string            `json:"displayName"`
	Template             string            `json:"template"`
	TTL                  int               `json:"ttl"`
	HealthCheckMonitorID string            `json:"healthCheckMonitorId"`
	Answers              []Answer          `json:"answers"`
	Rules                []Rule            `json:"rules"`
	FreeformTags         map[string]string `json:"freeformTags"`
}

func (c Config) policy(name, monitor string) Policy {
	var answers []Answer
	var cases []Case
	for _, region := range c.Regions {
		answers = append(answers, Answer{Name: region.Label, Rtype: "A", Rdata: region.IP, Pool: region.Label})
		ranked := slices.Clone(c.Regions)
		slices.SortStableFunc(ranked, func(a, b Region) int {
			return cmp.Compare(distance(region, a), distance(region, b))
		})
		for _, continent := range region.Continents {
			cases = append(cases, Case{CaseCondition: "query.client.geoKey in (geoKey '" + continentKeys[continent] + "')", AnswerData: priorities(ranked)})
		}
	}
	cases = append(cases, Case{AnswerData: priorities(c.Regions)})
	keep, one := true, 1
	return Policy{
		CompartmentID: c.CompartmentID, DisplayName: name, Template: "ROUTE_BY_GEO", TTL: c.TTL,
		HealthCheckMonitorID: monitor, Answers: answers, FreeformTags: c.tags("steering-policy", strings.SplitN(name, ".", 2)[0]),
		Rules: []Rule{
			{RuleType: "FILTER", DefaultAnswerData: []AnswerData{{AnswerCondition: "answer.isDisabled != true", ShouldKeep: &keep}}},
			{RuleType: "HEALTH"},
			{RuleType: "PRIORITY", Cases: cases},
			{RuleType: "LIMIT", DefaultCount: &one},
		},
	}
}

var continentKeys = map[string]string{
	"AF": "6255146", "AN": "6255152", "AS": "6255147", "EU": "6255148", "NA": "6255149", "OC": "6255151", "SA": "6255150",
}

func priorities(regions []Region) []AnswerData {
	data := make([]AnswerData, len(regions))
	for i, r := range regions {
		value := i + 1
		data[i] = AnswerData{AnswerCondition: "answer.pool == '" + r.Label + "'", Value: &value}
	}
	return data
}

func distance(a, b Region) float64 {
	rad := math.Pi / 180
	h := math.Pow(math.Sin((a.Latitude-b.Latitude)*rad/2), 2) + math.Cos(a.Latitude*rad)*math.Cos(b.Latitude*rad)*math.Pow(math.Sin((a.Longitude-b.Longitude)*rad/2), 2)
	return 2 * 6371 * math.Asin(math.Sqrt(h))
}
