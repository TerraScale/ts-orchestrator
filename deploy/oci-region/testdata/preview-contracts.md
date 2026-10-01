# Preview contract coverage

The native Go tables preserve all 52 upstream test methods after the shared OpenSSH policy update as 288 isolated API observations. Each case pins the complete return value or exception type/message, ordered dependency calls, and resulting files/modes. Shared JSON fixtures contain only data. Dependency command records use the unified bootstrap/release namespaces. Test time is supplied by Go so freshness/expiry inputs remain deterministic.

| Original test method | Native API cases |
| --- | --- |
| PreviewAdmissionTests.test_base_only_pre_import_cli_accepts_uploaded_base_receipt | `import_estimate` × 2, `main` × 2 |
| PreviewAdmissionTests.test_checked_in_plan_pins_reconciled_private_ports | `load_plan` × 1, `require_ocid` × 2 |
| PreviewAdmissionTests.test_collect_inventory_lists_gateway_kinds | `collect_inventory` × 1 |
| PreviewAdmissionTests.test_controller_storage_grants_only_signed_scope_versions_and_permissions | `load_plan` × 1, `estimate` × 1, `required_plan_bootstrap_prefix` × 9, `controller_storage_statements` × 2, `inspect_foundation` × 1 |
| PreviewAdmissionTests.test_current_head_uses_oci_cli_version_header_and_requires_it | `current_object_head` × 2 |
| PreviewAdmissionTests.test_empty_object_lists_use_exact_oci_cli_empty_shape | `oci` × 11 |
| PreviewAdmissionTests.test_expired_prior_admission_remains_lineage_only | `import_estimate` × 1, `verify_previous_import_admission` × 3 |
| PreviewAdmissionTests.test_extra_public_ip_or_backups_fail_closed | `estimate` × 2 |
| PreviewAdmissionTests.test_five_host_budget_includes_existing_resources_and_reserves | `estimate` × 1 |
| PreviewAdmissionTests.test_fixed_cell_mapping_rejects_unmapped_region | `load_plan` × 1 |
| PreviewAdmissionTests.test_forgejo_data_volume_and_preview_volumes_use_exact_plan_sizes | `estimate` × 2 |
| PreviewAdmissionTests.test_forgejo_data_volume_expectation_is_bounded | `load_plan` × 1 |
| PreviewAdmissionTests.test_full_projection_carries_exact_base_only_admission_lineage | `main` × 1, `import_estimate` × 3, `establish_base_lineage` × 3 |
| PreviewAdmissionTests.test_host_credential_requires_vaultsecret_ocid_kind | `load_plan` × 2 |
| PreviewAdmissionTests.test_host_secret_policy_is_exact_and_attached_to_selected_compartment | `load_plan` × 1, `estimate` × 1, `required_plan_bootstrap_prefix` × 3, `required_controller_statements` × 1, `required_netbird_statements` × 1, `check_live_iam` × 2 |
| PreviewAdmissionTests.test_image_collection_excludes_platform_images | `collect_scoped_images` × 1 |
| PreviewAdmissionTests.test_import_fails_closed_on_missing_or_duplicate_storage_facts | `import_estimate` × 5 |
| PreviewAdmissionTests.test_import_overbound_size_and_stale_inventory_deny | `import_estimate` × 4 |
| PreviewAdmissionTests.test_import_three_gates_count_versions_and_actual_image_gib | `import_estimate` × 14, `estimate` × 1 |
| PreviewAdmissionTests.test_inspection_readback_binds_fresh_plan_inventory_and_cell | `load_plan` × 1, `estimate` × 1, `inspect_foundation` × 2 |
| PreviewAdmissionTests.test_inspection_rejects_admission_that_expires_during_live_reads | `load_plan` × 1, `estimate` × 1, `inspect_foundation` × 1 |
| PreviewAdmissionTests.test_inventory_admits_only_recorded_gateways_and_balancer | `load_plan` × 1, `estimate` × 1, `verify_inventory` × 12 |
| PreviewAdmissionTests.test_kms_key_must_be_enabled_not_merely_active | `load_plan` × 1, `estimate` × 1, `check_live_vault` × 2 |
| PreviewAdmissionTests.test_live_network_requires_every_planned_route_identity | `load_plan` × 1, `estimate` × 1, `check_live_network` × 3, `required_resource_ids` × 5 |
| PreviewAdmissionTests.test_live_network_rules_routes_and_operator_gateway_are_exact | `load_plan` × 1, `estimate` × 1, `check_live_network` × 27 |
| PreviewAdmissionTests.test_live_network_without_gateway_reads_no_peering | `load_plan` × 1, `estimate` × 1, `check_live_network` × 1 |
| PreviewAdmissionTests.test_monthly_ceiling_accepts_200_and_rejects_more | `load_plan` × 3, `estimate` × 3 |
| PreviewAdmissionTests.test_netbird_egress_is_exact_private_https_and_stun | `load_plan` × 8 |
| PreviewAdmissionTests.test_netbird_foundation_requires_secret_and_policy_and_exact_readback | `load_plan` × 1, `estimate` × 1, `required_netbird_statements` × 3, `check_live_netbird_iam` × 5, `required_resource_ids` × 3 |
| PreviewAdmissionTests.test_netbird_plan_contains_only_private_manager_and_secret_references | `load_plan` × 10 |
| PreviewAdmissionTests.test_normal_estimate_prices_scoped_custom_images | `estimate` × 2 |
| PreviewAdmissionTests.test_object_growth_and_staging_reserves_are_separate_and_bounded | `estimate` × 1, `load_plan` × 2 |
| PreviewAdmissionTests.test_object_growth_can_exceed_budget | `estimate` × 1 |
| PreviewAdmissionTests.test_one_replacement_overlap_expires_after_72_hours | `estimate` × 2 |
| PreviewAdmissionTests.test_operator_gateway_private_outside_cell_inside_its_vcn | `load_plan` × 10 |
| PreviewAdmissionTests.test_public_api_subnet_inside_cell_outside_private_subnet | `load_plan` × 8 |
| PreviewAdmissionTests.test_public_subnet_reaches_members_only_on_client_port | `load_plan` × 4 |
| PreviewAdmissionTests.test_route_rules_service_gateway_plus_single_gateway_peering | `load_plan` × 7 |
| PreviewAdmissionTests.test_rule_sources_limited_to_cell_or_gateway | `load_plan` × 14 |
| PreviewAdmissionTests.test_seed_a_requires_exact_plan_ocid_and_bootstrap_create_key | `estimate` × 1 |
| PreviewAdmissionTests.test_seed_create_identity_survives_recording_the_launched_instance | `load_plan` × 3, `create_identity` × 3 |
| PreviewAdmissionTests.test_seed_launch_carries_launch_material_and_rejects_drift | `seed_launch` × 5 |
| PreviewAdmissionTests.test_seed_preflight_binds_foundation_and_signed_image | `estimate` × 1, `verify_seed_preflight` × 13, `create_identity` × 1, `canonical_manual_seed_plan` × 1 |
| PreviewAdmissionTests.test_seed_preflight_uses_verified_anchor_command | `seed_preflight` × 1 |
| PreviewAdmissionTests.test_stale_inventory_fails_closed | `estimate` × 1 |
| PreviewAdmissionTests.test_unbudgeted_instance_fails_closed | `estimate` × 1 |
| PreviewAdmissionTests.test_unknown_paid_network_resource_fails_closed | `estimate` × 1 |
| PreviewAdmissionTests.test_versioned_bucket_fails_closed | `estimate` × 1 |
| PreviewBaseInventoryTests.test_base_only_cli_import_chain_and_full_projection_transition | `main` × 8 |
| PreviewBaseInventoryTests.test_full_projection_import_inventory_carries_prior_base_receipt | `main` × 1 |
| PreviewBaseInventoryTests.test_full_projection_import_inventory_rejects_tampered_carried_image_identity | `main` × 1 |
| PreviewBaseInventoryTests.test_full_projection_import_inventory_requires_exact_base_receipt_hash | `main` × 1 |
