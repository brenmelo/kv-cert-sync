locals {
  destinations = { for k, id in var.destination_vault_ids : k => { vault_id = id } }
}

module "hub" {
  source = "../modules/hub"

  suffix              = var.suffix
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = merge({ purpose = "kv-cert-sync", environment = "production" }, var.tags)

  network_mode                    = "private"
  source_purge_protection_enabled = true
  operator_object_id              = "" # no human gets standing data-plane access to the factory vault
  destination_role_mode           = var.destination_role_mode
  destinations                    = local.destinations
  key_vault_dns_suffix            = var.key_vault_dns_suffix
  sync_secret_name_prefix         = var.sync_secret_name_prefix

  enable_renew_app = var.enable_renew_app
  ca_provider      = var.ca_provider
  renew_settings   = var.digicert_settings

  reconcile_schedule = var.reconcile_schedule
  renew_schedule     = var.renew_schedule

  function_source = {
    sync  = abspath("${path.module}/../../src/sync")
    renew = abspath("${path.module}/../../src/renew")
  }

  storage_replication_type = var.storage_replication_type
  log_retention_days       = var.log_retention_days

  private_endpoint_subnet_id = var.private_endpoint_subnet_id
  function_subnet_ids        = var.function_subnet_ids
  private_dns_zone_ids       = var.private_dns_zone_ids

  alert_email_addresses = var.alert_email_addresses
}
