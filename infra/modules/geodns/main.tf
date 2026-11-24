terraform {
  required_providers {
    oci = {
      source = "oracle/oci"
    }
  }
}

locals {
  continent_geo_keys = {
    AF = "6255146"
    AS = "6255147"
    EU = "6255148"
    NA = "6255149"
    SA = "6255150"
    OC = "6255151"
    AN = "6255152"
  }

  fallback_rank = { for index, label in var.rollout_order : label => index }

  region_cases = {
    for label, region in var.regions : label => join(", ", [
      for continent in region.continents : "geoKey '${local.continent_geo_keys[continent]}'"
    ])
  }
}

resource "oci_dns_zone" "this" {
  compartment_id = var.compartment_id
  name           = var.zone
  zone_type      = "PRIMARY"
}

resource "oci_dns_rrset" "regional_api" {
  for_each = var.regions

  zone_name_or_id = oci_dns_zone.this.id
  domain          = "${each.key}.api.${var.zone}"
  rtype           = "A"

  items {
    domain = "${each.key}.api.${var.zone}"
    rtype  = "A"
    rdata  = each.value.nlb_ip
    ttl    = var.ttl_seconds
  }
}

resource "oci_dns_rrset" "regional_pg" {
  for_each = var.regions

  zone_name_or_id = oci_dns_zone.this.id
  domain          = "${each.key}.pg.${var.zone}"
  rtype           = "A"

  items {
    domain = "${each.key}.pg.${var.zone}"
    rtype  = "A"
    rdata  = each.value.nlb_ip
    ttl    = var.ttl_seconds
  }
}

resource "oci_dns_rrset" "pinned" {
  for_each = var.pinned_names

  zone_name_or_id = oci_dns_zone.this.id
  domain          = each.key
  rtype           = "A"

  items {
    domain = each.key
    rtype  = "A"
    rdata  = var.regions[each.value].nlb_ip
    ttl    = var.ttl_seconds
  }
}

resource "oci_health_checks_http_monitor" "readyz" {
  compartment_id      = var.compartment_id
  display_name        = "ts-edge-readyz"
  protocol            = "HTTP"
  method              = "GET"
  port                = 80
  path                = var.health_check_path
  interval_in_seconds = 30
  timeout_in_seconds  = 10
  is_enabled          = true
  targets             = [for label in sort(keys(var.regions)) : var.regions[label].nlb_ip]
}

resource "oci_dns_steering_policy" "geo" {
  for_each = toset(var.steered_names)

  compartment_id          = var.compartment_id
  display_name            = replace(each.key, ".", "-")
  template                = "ROUTE_BY_GEO"
  ttl                     = var.ttl_seconds
  health_check_monitor_id = oci_health_checks_http_monitor.readyz.id

  dynamic "answers" {
    for_each = var.regions

    content {
      name        = answers.key
      pool        = answers.key
      rtype       = "A"
      rdata       = answers.value.nlb_ip
      is_disabled = false
    }
  }

  rules {
    rule_type = "FILTER"

    default_answer_data {
      answer_condition = "answer.isDisabled != true"
      should_keep      = true
    }
  }

  rules {
    rule_type = "HEALTH"
  }

  rules {
    rule_type = "PRIORITY"

    dynamic "default_answer_data" {
      for_each = var.regions

      content {
        answer_condition = "answer.pool == '${default_answer_data.key}'"
        value            = lookup(local.fallback_rank, default_answer_data.key, length(var.rollout_order))
      }
    }

    dynamic "cases" {
      for_each = local.region_cases

      content {
        case_condition = "query.client.geoKey in (${cases.value})"

        dynamic "answer_data" {
          for_each = var.regions

          content {
            answer_condition = "answer.pool == '${answer_data.key}'"
            value            = answer_data.key == cases.key ? 0 : 1 + lookup(local.fallback_rank, answer_data.key, length(var.rollout_order))
          }
        }
      }
    }
  }

  rules {
    rule_type     = "LIMIT"
    default_count = 1
  }
}

resource "oci_dns_steering_policy_attachment" "geo" {
  for_each = oci_dns_steering_policy.geo

  zone_id            = oci_dns_zone.this.id
  domain_name        = each.key
  steering_policy_id = each.value.id
  display_name       = replace(each.key, ".", "-")
}
