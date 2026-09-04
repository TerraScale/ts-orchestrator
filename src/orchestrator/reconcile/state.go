// Package reconcile drives the observed cloud estate to the declared estate
// (D-67). The declared estate is typed configuration in the estate package;
// provider adapters (OCI, Cloudflare) implement Reconciler, observe their
// resource kinds into the provider-neutral State form defined here, and apply
// the plans the loop derives from it.
package reconcile

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/estate"
)

// Attribute is one normalized configuration fact of a resource. The diff is
// attribute-by-attribute, so a provider observation must report exactly the
// attribute names the declared renderer emits for the resource kind.
type Attribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Resource is one observed or declared resource in provider-neutral form.
// Attributes is a multiset: repeated names (rules, entries, DNS names) are
// compared order-insensitively.
type Resource struct {
	Ref        estate.ResourceRef `json:"ref"`
	Attributes []Attribute        `json:"attributes"`
}

// State is the observed or declared estate in provider-neutral form.
type State struct {
	Resources []Resource `json:"resources"`
}

// RefKey is the map key form of a resource identity.
func RefKey(ref estate.ResourceRef) string {
	return string(ref.Kind) + "/" + ref.Region + "/" + ref.Name
}

// ByRef indexes the state by resource identity. Duplicate identities are an
// observation bug and are reported instead of silently collapsed.
func (s State) ByRef() (map[string]Resource, error) {
	indexed := make(map[string]Resource, len(s.Resources))
	for _, resource := range s.Resources {
		key := RefKey(resource.Ref)
		if _, exists := indexed[key]; exists {
			return nil, fmt.Errorf("duplicate observed resource %s", key)
		}
		indexed[key] = resource
	}
	return indexed, nil
}

// Declared renders the declared estate into the provider-neutral State. This
// function defines the observation contract: for each resource kind, the
// attribute names below are the exact names a provider adapter must report.
//
//	compute               member.count, member.primary-shape, member.fallback-shape,
//	                      member.ocpus, member.memory-gib, member.boot-volume-gib,
//	                      member.data-volume-gib, member.control-replicas
//	network               network.cidr
//	subnet                subnet.cidr
//	nsg                   nsg.rule = "<direction>|<protocol>|<peer>|<min>-<max>"
//	bucket                bucket.purpose, bucket.versioning,
//	                      bucket.lifecycle-rule = "<name>|<action>|<after-days>[|keep-<n>]"
//	vault-key             vault-key.purpose, vault-key.rotation-hours
//	certificate           certificate.purpose, certificate.renew-before-hours,
//	                      certificate.dns-name (repeated)
//	dns-record            dns.type, dns.content, dns.proxied, dns.ttl
//	cache-rule            cache.hostname, cache.path-prefix, cache.eligible,
//	                      cache.immutable, cache.edge-ttl-seconds, cache.smart-tiered,
//	                      cache.tag-pattern
//	snippet-rule          snippet.hostname, snippet.path-prefix,
//	                      snippet.source-file, snippet.secret (repeated)
//	worker-route          route.hostname, route.path-prefix, route.script
//	kv-map                kv.namespace, kv.entry = "<key>=<value>" (repeated)
//	waf-rule              waf.expression, waf.action
//	rate-rule             rate.expression, rate.requests, rate.period-seconds,
//	                      rate.mitigation-seconds
//	capability-key        capability.member-secret, capability.edge-secret,
//	                      capability.rotation-hours, capability.overlap-hours
func Declared(spec estate.Spec) (State, error) {
	if err := spec.Validate(); err != nil {
		return State{}, err
	}
	var state State
	for _, region := range spec.Regions {
		state.Resources = append(state.Resources,
			Resource{
				Ref: estate.ResourceRef{Kind: estate.ResourceCompute, Region: region.Code, Name: "members"},
				Attributes: []Attribute{
					{Name: "member.count", Value: strconv.FormatUint(uint64(region.Members.Count), 10)},
					{Name: "member.primary-shape", Value: region.Members.PrimaryShape},
					{Name: "member.fallback-shape", Value: region.Members.FallbackShape},
					{Name: "member.ocpus", Value: strconv.FormatUint(uint64(region.Members.OCPUs), 10)},
					{Name: "member.memory-gib", Value: strconv.FormatUint(uint64(region.Members.MemoryGiB), 10)},
					{Name: "member.boot-volume-gib", Value: strconv.FormatUint(uint64(region.Members.BootVolumeGiB), 10)},
					{Name: "member.data-volume-gib", Value: strconv.FormatUint(uint64(region.Members.DataVolumeGiB), 10)},
					{Name: "member.control-replicas", Value: strconv.FormatUint(uint64(region.Members.ControlReplicas), 10)},
				},
			},
			Resource{
				Ref: estate.ResourceRef{Kind: estate.ResourceNetwork, Region: region.Code, Name: "vcn"},
				Attributes: []Attribute{
					{Name: "network.cidr", Value: region.Network.CIDR},
				},
			},
		)
		for _, subnet := range region.Network.Subnets {
			state.Resources = append(state.Resources, Resource{
				Ref:        estate.ResourceRef{Kind: estate.ResourceSubnet, Region: region.Code, Name: subnet.Name},
				Attributes: []Attribute{{Name: "subnet.cidr", Value: subnet.CIDR}},
			})
		}
		for _, group := range region.Network.SecurityGroups {
			attributes := make([]Attribute, 0, len(group.Rules))
			for _, rule := range group.Rules {
				attributes = append(attributes, Attribute{Name: "nsg.rule", Value: securityRuleValue(rule)})
			}
			state.Resources = append(state.Resources, Resource{
				Ref:        estate.ResourceRef{Kind: estate.ResourceNSG, Region: region.Code, Name: group.Name},
				Attributes: attributes,
			})
		}
		for _, bucket := range region.Buckets {
			attributes := []Attribute{
				{Name: "bucket.purpose", Value: bucket.Purpose},
				{Name: "bucket.versioning", Value: strconv.FormatBool(bucket.Versioning)},
			}
			for _, rule := range bucket.LifecycleRules {
				value := rule.Name + "|" + rule.Action + "|" + strconv.FormatUint(uint64(rule.AfterDays), 10)
				if rule.KeepLatest > 0 {
					value += "|keep-" + strconv.FormatUint(uint64(rule.KeepLatest), 10)
				}
				attributes = append(attributes, Attribute{Name: "bucket.lifecycle-rule", Value: value})
			}
			state.Resources = append(state.Resources, Resource{
				Ref:        estate.ResourceRef{Kind: estate.ResourceBucket, Region: region.Code, Name: bucket.Name},
				Attributes: attributes,
			})
		}
		for _, key := range region.VaultKeys {
			state.Resources = append(state.Resources, Resource{
				Ref: estate.ResourceRef{Kind: estate.ResourceVaultKey, Region: region.Code, Name: key.Name},
				Attributes: []Attribute{
					{Name: "vault-key.purpose", Value: key.Purpose},
					{Name: "vault-key.rotation-hours", Value: strconv.FormatUint(uint64(key.RotationHours), 10)},
				},
			})
		}
		for _, certificate := range region.Certificates {
			attributes := []Attribute{
				{Name: "certificate.purpose", Value: certificate.Purpose},
				{Name: "certificate.renew-before-hours", Value: strconv.FormatUint(uint64(certificate.RenewBeforeHours), 10)},
			}
			for _, name := range certificate.DNSNames {
				attributes = append(attributes, Attribute{Name: "certificate.dns-name", Value: name})
			}
			state.Resources = append(state.Resources, Resource{
				Ref:        estate.ResourceRef{Kind: estate.ResourceCertificate, Region: region.Code, Name: certificate.Name},
				Attributes: attributes,
			})
		}
	}
	cloud := spec.Cloudflare
	for _, record := range cloud.DNSRecords {
		state.Resources = append(state.Resources, Resource{
			Ref: estate.ResourceRef{Kind: estate.ResourceDNS, Name: record.Name},
			Attributes: []Attribute{
				{Name: "dns.type", Value: record.Type},
				{Name: "dns.content", Value: record.Content},
				{Name: "dns.proxied", Value: strconv.FormatBool(record.Proxied)},
				{Name: "dns.ttl", Value: strconv.FormatUint(uint64(record.TTL), 10)},
			},
		})
	}
	for _, rule := range cloud.CacheRules {
		state.Resources = append(state.Resources, Resource{
			Ref: estate.ResourceRef{Kind: estate.ResourceCacheRule, Name: rule.Name},
			Attributes: []Attribute{
				{Name: "cache.hostname", Value: rule.Hostname},
				{Name: "cache.path-prefix", Value: rule.PathPrefix},
				{Name: "cache.eligible", Value: strconv.FormatBool(rule.Eligible)},
				{Name: "cache.immutable", Value: strconv.FormatBool(rule.Immutable)},
				{Name: "cache.edge-ttl-seconds", Value: strconv.FormatUint(uint64(rule.EdgeTTLSeconds), 10)},
				{Name: "cache.smart-tiered", Value: strconv.FormatBool(rule.SmartTiered)},
				{Name: "cache.tag-pattern", Value: rule.CacheTagPattern},
			},
		})
	}
	for _, rule := range cloud.SnippetRules {
		attributes := []Attribute{
			{Name: "snippet.hostname", Value: rule.Hostname},
			{Name: "snippet.path-prefix", Value: rule.PathPrefix},
			{Name: "snippet.source-file", Value: rule.SourceFile},
		}
		for _, secret := range rule.SecretNames {
			attributes = append(attributes, Attribute{Name: "snippet.secret", Value: secret})
		}
		state.Resources = append(state.Resources, Resource{
			Ref:        estate.ResourceRef{Kind: estate.ResourceSnippetRule, Name: rule.Name},
			Attributes: attributes,
		})
	}
	for _, route := range cloud.WorkerRoutes {
		state.Resources = append(state.Resources, Resource{
			Ref: estate.ResourceRef{Kind: estate.ResourceWorkerRoute, Name: route.Name},
			Attributes: []Attribute{
				{Name: "route.hostname", Value: route.Hostname},
				{Name: "route.path-prefix", Value: route.PathPrefix},
				{Name: "route.script", Value: route.ScriptName},
			},
		})
	}
	for _, mapping := range cloud.KVMaps {
		attributes := []Attribute{{Name: "kv.namespace", Value: mapping.Namespace}}
		for _, entry := range mapping.Entries {
			attributes = append(attributes, Attribute{Name: "kv.entry", Value: entry.Key + "=" + entry.Value})
		}
		state.Resources = append(state.Resources, Resource{
			Ref:        estate.ResourceRef{Kind: estate.ResourceKVMap, Name: mapping.Name},
			Attributes: attributes,
		})
	}
	for _, rule := range cloud.WAFRules {
		state.Resources = append(state.Resources, Resource{
			Ref: estate.ResourceRef{Kind: estate.ResourceWAFRule, Name: rule.Name},
			Attributes: []Attribute{
				{Name: "waf.expression", Value: rule.Expression},
				{Name: "waf.action", Value: rule.Action},
			},
		})
	}
	for _, rule := range cloud.RateRules {
		state.Resources = append(state.Resources, Resource{
			Ref: estate.ResourceRef{Kind: estate.ResourceRateRule, Name: rule.Name},
			Attributes: []Attribute{
				{Name: "rate.expression", Value: rule.Expression},
				{Name: "rate.requests", Value: strconv.FormatUint(uint64(rule.Requests), 10)},
				{Name: "rate.period-seconds", Value: strconv.FormatUint(uint64(rule.PeriodSeconds), 10)},
				{Name: "rate.mitigation-seconds", Value: strconv.FormatUint(uint64(rule.MitigationTime), 10)},
			},
		})
	}
	for _, key := range cloud.CapabilityKeys {
		state.Resources = append(state.Resources, Resource{
			Ref: estate.ResourceRef{Kind: estate.ResourceCapabilityKey, Name: key.Name},
			Attributes: []Attribute{
				{Name: "capability.member-secret", Value: key.MemberSecretName},
				{Name: "capability.edge-secret", Value: key.EdgeSecretName},
				{Name: "capability.rotation-hours", Value: strconv.FormatUint(uint64(key.RotationHours), 10)},
				{Name: "capability.overlap-hours", Value: strconv.FormatUint(uint64(key.OverlapHours), 10)},
			},
		})
	}
	return state, nil
}

func securityRuleValue(rule estate.NetworkSecurityRule) string {
	return strings.Join([]string{
		rule.Direction,
		rule.Protocol,
		rule.Peer,
		strconv.FormatUint(uint64(rule.PortMin), 10) + "-" + strconv.FormatUint(uint64(rule.PortMax), 10),
	}, "|")
}

// normalizeAttributes sorts attributes by name then value, making attribute
// multisets directly comparable.
func normalizeAttributes(attributes []Attribute) []Attribute {
	normalized := append([]Attribute(nil), attributes...)
	sort.Slice(normalized, func(i, j int) bool {
		if normalized[i].Name != normalized[j].Name {
			return normalized[i].Name < normalized[j].Name
		}
		return normalized[i].Value < normalized[j].Value
	})
	return normalized
}
