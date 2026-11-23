terraform {
  required_providers {
    oci = {
      source = "oracle/oci"
    }
  }
}

locals {
  name               = "ts-${var.label}"
  availability_names = data.oci_identity_availability_domains.this.availability_domains[*].name
  fault_domains      = ["FAULT-DOMAIN-1", "FAULT-DOMAIN-2", "FAULT-DOMAIN-3"]
  public_tcp_ports   = [80, 443, 5432]
  backend_sets       = { for port in local.public_tcp_ports : "tcp-${port}" => port }
  shapes             = toset([var.stateful_shape.name, var.worker_shape.name])
  data_device        = "/dev/oracleoci/oraclevdb"

  stateful_placement = [
    for index in range(var.stateful_count) : {
      availability_domain = local.availability_names[index % length(local.availability_names)]
      fault_domain        = local.fault_domains[index % length(local.fault_domains)]
    }
  ]

  stateful_backends = {
    for pair in setproduct(keys(local.backend_sets), range(var.stateful_count)) :
    "${pair[0]}-${pair[1]}" => { backend_set = pair[0], index = pair[1] }
  }

  node_metadata = {
    for pool in ["stateful", "worker"] : pool => merge(
      {
        user_data             = base64encode(var.boot_script)
        ts_region             = var.label
        ts_pool               = pool
        ts_vcn_cidr           = var.vcn_cidr
        ts_orch_bundle_url    = var.bundle_url
        ts_orch_bundle_sha256 = var.bundle_sha256
      },
      length(var.netbird_udp_ports) > 0 ? { ts_netbird_udp_ports = join(",", var.netbird_udp_ports) } : {}
    )
  }
}

data "oci_identity_availability_domains" "this" {
  compartment_id = var.tenancy_id
}

data "oci_core_services" "all" {
  filter {
    name   = "name"
    values = ["All .* Services In Oracle Services Network"]
    regex  = true
  }
}

data "oci_core_images" "ubuntu" {
  for_each = local.shapes

  compartment_id           = var.compartment_id
  operating_system         = "Canonical Ubuntu"
  operating_system_version = "24.04"
  shape                    = each.key
  state                    = "AVAILABLE"
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"

  filter {
    name   = "display_name"
    values = ["^Canonical-Ubuntu-24\\.04-(aarch64-)?[0-9]{4}\\."]
    regex  = true
  }
}

data "oci_core_volume_backup_policies" "oracle" {
  filter {
    name   = "display_name"
    values = ["silver"]
  }
}

resource "oci_core_vcn" "this" {
  compartment_id = var.compartment_id
  display_name   = "${local.name}-vcn"
  cidr_blocks    = [var.vcn_cidr]
  dns_label      = "ts${var.label}"
}

resource "oci_core_internet_gateway" "this" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.this.id
  display_name   = "${local.name}-igw"
  enabled        = true
}

resource "oci_core_nat_gateway" "this" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.this.id
  display_name   = "${local.name}-nat"
}

resource "oci_core_service_gateway" "this" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.this.id
  display_name   = "${local.name}-sgw"

  services {
    service_id = data.oci_core_services.all.services[0].id
  }
}

resource "oci_core_route_table" "public" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.this.id
  display_name   = "${local.name}-public-rt"

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.this.id
  }
}

resource "oci_core_route_table" "private" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.this.id
  display_name   = "${local.name}-private-rt"

  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_nat_gateway.this.id
  }

  route_rules {
    destination       = data.oci_core_services.all.services[0].cidr_block
    destination_type  = "SERVICE_CIDR_BLOCK"
    network_entity_id = oci_core_service_gateway.this.id
  }
}

resource "oci_core_security_list" "nsg_only" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.this.id
  display_name   = "${local.name}-nsg-only"
}

resource "oci_core_subnet" "public" {
  compartment_id             = var.compartment_id
  vcn_id                     = oci_core_vcn.this.id
  display_name               = "${local.name}-public"
  cidr_block                 = var.public_subnet_cidr
  dns_label                  = "edge"
  route_table_id             = oci_core_route_table.public.id
  security_list_ids          = [oci_core_security_list.nsg_only.id]
  prohibit_public_ip_on_vnic = false
}

resource "oci_core_subnet" "private" {
  compartment_id             = var.compartment_id
  vcn_id                     = oci_core_vcn.this.id
  display_name               = "${local.name}-private"
  cidr_block                 = var.private_subnet_cidr
  dns_label                  = "nodes"
  route_table_id             = oci_core_route_table.private.id
  security_list_ids          = [oci_core_security_list.nsg_only.id]
  prohibit_public_ip_on_vnic = true
}

resource "oci_core_network_security_group" "nlb" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.this.id
  display_name   = "${local.name}-nlb-nsg"
}

resource "oci_core_network_security_group" "node" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.this.id
  display_name   = "${local.name}-node-nsg"
}

resource "oci_core_network_security_group_security_rule" "nlb_ingress_tcp" {
  for_each = local.backend_sets

  network_security_group_id = oci_core_network_security_group.nlb.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = "0.0.0.0/0"
  source_type               = "CIDR_BLOCK"
  stateless                 = false

  tcp_options {
    destination_port_range {
      min = each.value
      max = each.value
    }
  }
}

resource "oci_core_network_security_group_security_rule" "nlb_egress_nodes" {
  network_security_group_id = oci_core_network_security_group.nlb.id
  direction                 = "EGRESS"
  protocol                  = "6"
  destination               = var.private_subnet_cidr
  destination_type          = "CIDR_BLOCK"
  stateless                 = false
}

resource "oci_core_network_security_group_security_rule" "node_ingress_tcp" {
  for_each = local.backend_sets

  network_security_group_id = oci_core_network_security_group.node.id
  direction                 = "INGRESS"
  protocol                  = "6"
  source                    = "0.0.0.0/0"
  source_type               = "CIDR_BLOCK"
  stateless                 = false

  tcp_options {
    destination_port_range {
      min = each.value
      max = each.value
    }
  }
}

resource "oci_core_network_security_group_security_rule" "node_ingress_vcn" {
  network_security_group_id = oci_core_network_security_group.node.id
  direction                 = "INGRESS"
  protocol                  = "all"
  source                    = var.vcn_cidr
  source_type               = "CIDR_BLOCK"
  stateless                 = false
}

resource "oci_core_network_security_group_security_rule" "node_ingress_netbird_udp" {
  for_each = toset([for port in var.netbird_udp_ports : tostring(port)])

  network_security_group_id = oci_core_network_security_group.node.id
  direction                 = "INGRESS"
  protocol                  = "17"
  source                    = "0.0.0.0/0"
  source_type               = "CIDR_BLOCK"
  stateless                 = false

  udp_options {
    destination_port_range {
      min = tonumber(each.value)
      max = tonumber(each.value)
    }
  }
}

resource "oci_core_network_security_group_security_rule" "node_egress_all" {
  network_security_group_id = oci_core_network_security_group.node.id
  direction                 = "EGRESS"
  protocol                  = "all"
  destination               = "0.0.0.0/0"
  destination_type          = "CIDR_BLOCK"
  stateless                 = false
}

resource "oci_core_public_ip" "nlb" {
  compartment_id = var.compartment_id
  display_name   = "${local.name}-nlb-ip"
  lifetime       = "RESERVED"

  lifecycle {
    ignore_changes = [private_ip_id]
  }
}

resource "oci_network_load_balancer_network_load_balancer" "this" {
  compartment_id                 = var.compartment_id
  display_name                   = "${local.name}-nlb"
  subnet_id                      = oci_core_subnet.public.id
  is_private                     = false
  is_preserve_source_destination = false
  network_security_group_ids     = [oci_core_network_security_group.nlb.id]

  reserved_ips {
    id = oci_core_public_ip.nlb.id
  }
}

resource "oci_network_load_balancer_backend_set" "tcp" {
  for_each = local.backend_sets

  network_load_balancer_id = oci_network_load_balancer_network_load_balancer.this.id
  name                     = each.key
  policy                   = "FIVE_TUPLE"
  is_preserve_source       = true
  is_fail_open             = false

  health_checker {
    protocol           = "HTTP"
    port               = 80
    url_path           = "/readyz"
    return_code        = 200
    interval_in_millis = 10000
    timeout_in_millis  = 3000
    retries            = 3
  }
}

resource "oci_network_load_balancer_listener" "tcp" {
  for_each = local.backend_sets

  network_load_balancer_id = oci_network_load_balancer_network_load_balancer.this.id
  name                     = each.key
  default_backend_set_name = oci_network_load_balancer_backend_set.tcp[each.key].name
  port                     = each.value
  protocol                 = "TCP"
}

resource "oci_core_instance" "stateful" {
  count = var.stateful_count

  compartment_id      = var.compartment_id
  availability_domain = local.stateful_placement[count.index].availability_domain
  fault_domain        = local.stateful_placement[count.index].fault_domain
  display_name        = "${local.name}-stateful-${count.index + 1}"
  shape               = var.stateful_shape.name
  metadata            = local.node_metadata.stateful

  freeform_tags = {
    "ts-region" = var.label
    "ts-pool"   = "stateful"
  }

  shape_config {
    ocpus         = var.stateful_shape.ocpus
    memory_in_gbs = var.stateful_shape.memoryGiB
  }

  source_details {
    source_type             = "image"
    source_id               = data.oci_core_images.ubuntu[var.stateful_shape.name].images[0].id
    boot_volume_size_in_gbs = var.stateful_shape.bootGiB
  }

  create_vnic_details {
    subnet_id        = oci_core_subnet.private.id
    assign_public_ip = false
    hostname_label   = "${local.name}-stateful-${count.index + 1}"
    nsg_ids          = [oci_core_network_security_group.node.id]
  }

  instance_options {
    are_legacy_imds_endpoints_disabled = true
  }

  availability_config {
    recovery_action = "RESTORE_INSTANCE"
  }

  lifecycle {
    ignore_changes = [metadata, source_details[0].source_id]
  }
}

resource "oci_core_volume" "stateful_data" {
  count = var.stateful_count

  compartment_id       = var.compartment_id
  availability_domain  = local.stateful_placement[count.index].availability_domain
  display_name         = "${local.name}-stateful-${count.index + 1}-data"
  size_in_gbs          = var.stateful_data_gib
  vpus_per_gb          = var.stateful_data_vpus
  is_auto_tune_enabled = true

  freeform_tags = {
    "ts-region" = var.label
    "ts-pool"   = "stateful"
  }

  lifecycle {
    prevent_destroy = true
    ignore_changes  = [size_in_gbs]
  }
}

resource "oci_core_volume_backup_policy_assignment" "stateful_data" {
  count = var.stateful_count

  asset_id  = oci_core_volume.stateful_data[count.index].id
  policy_id = data.oci_core_volume_backup_policies.oracle.volume_backup_policies[0].id
}

resource "oci_core_volume_attachment" "stateful_data" {
  count = var.stateful_count

  attachment_type = "paravirtualized"
  instance_id     = oci_core_instance.stateful[count.index].id
  volume_id       = oci_core_volume.stateful_data[count.index].id
  device          = local.data_device
  display_name    = "${local.name}-stateful-${count.index + 1}-data"
}

resource "oci_network_load_balancer_backend" "stateful" {
  for_each = local.stateful_backends

  network_load_balancer_id = oci_network_load_balancer_network_load_balancer.this.id
  backend_set_name         = oci_network_load_balancer_backend_set.tcp[each.value.backend_set].name
  target_id                = oci_core_instance.stateful[each.value.index].id
  port                     = local.backend_sets[each.value.backend_set]
}

resource "oci_core_instance_configuration" "worker" {
  compartment_id = var.compartment_id
  display_name   = "${local.name}-worker"

  instance_details {
    instance_type = "compute"

    launch_details {
      compartment_id = var.compartment_id
      shape          = var.worker_shape.name
      metadata       = local.node_metadata.worker

      freeform_tags = {
        "ts-region" = var.label
        "ts-pool"   = "worker"
      }

      shape_config {
        ocpus         = var.worker_shape.ocpus
        memory_in_gbs = var.worker_shape.memoryGiB
      }

      source_details {
        source_type             = "image"
        image_id                = data.oci_core_images.ubuntu[var.worker_shape.name].images[0].id
        boot_volume_size_in_gbs = var.worker_shape.bootGiB
      }

      create_vnic_details {
        assign_public_ip = false
        nsg_ids          = [oci_core_network_security_group.node.id]
      }

      instance_options {
        are_legacy_imds_endpoints_disabled = true
      }

      availability_config {
        recovery_action = "RESTORE_INSTANCE"
      }
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "oci_core_instance_pool" "worker" {
  compartment_id            = var.compartment_id
  display_name              = "${local.name}-worker"
  instance_configuration_id = oci_core_instance_configuration.worker.id
  size                      = var.worker_min

  freeform_tags = {
    "ts-region"   = var.label
    "ts-pool"     = "worker"
    "ts-max-size" = tostring(var.worker_max)
  }

  dynamic "placement_configurations" {
    for_each = local.availability_names

    content {
      availability_domain = placement_configurations.value
      primary_subnet_id   = oci_core_subnet.private.id
      fault_domains       = local.fault_domains
    }
  }

  dynamic "load_balancers" {
    for_each = local.backend_sets

    content {
      load_balancer_id = oci_network_load_balancer_network_load_balancer.this.id
      backend_set_name = oci_network_load_balancer_backend_set.tcp[load_balancers.key].name
      port             = load_balancers.value
      vnic_selection   = "PrimaryVnic"
    }
  }

  depends_on = [oci_network_load_balancer_listener.tcp, oci_network_load_balancer_backend.stateful]

  lifecycle {
    ignore_changes = [size]
  }
}
