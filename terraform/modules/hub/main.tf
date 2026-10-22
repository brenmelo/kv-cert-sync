data "azurerm_client_config" "current" {}

locals {
  sub_id    = data.azurerm_client_config.current.subscription_id
  tenant_id = data.azurerm_client_config.current.tenant_id
  public    = var.network_mode == "public"
  private   = var.network_mode == "private"

  # Everything about a destination is derived from its resource id, so the vault can live in any subscription.
  dest = {
    for k, d in var.destinations : k => {
      id   = d.vault_id
      sub  = element(split("/", d.vault_id), 2)
      name = element(split("/", d.vault_id), 8)
      uri  = "https://${element(split("/", d.vault_id), 8)}.${var.key_vault_dns_suffix}/"
    }
  }
  dest_json = jsonencode([for k, d in local.dest : { key = k, uri = d.uri }])

  role_scopes = distinct(concat(["/subscriptions/${local.sub_id}"], [for d in local.dest : "/subscriptions/${d.sub}"]))

  # Built-in roles are referenced by name. azurerm keeps role definition ids in the subscription-scoped form
  # (/subscriptions/<id>/providers/...), so writing the tenant-level GUID path makes every plan propose to replace the assignment.
  role_name = {
    cert_user         = "Key Vault Certificate User"
    cert_officer      = "Key Vault Certificates Officer"
    secrets_user      = "Key Vault Secrets User"
    kv_admin          = "Key Vault Administrator"
    blob_owner        = "Storage Blob Data Owner"
    blob_contributor  = "Storage Blob Data Contributor"
    queue_contributor = "Storage Queue Data Contributor"
    table_contributor = "Storage Table Data Contributor"
    queue_sender      = "Storage Queue Data Message Sender"
    metrics_publisher = "Monitoring Metrics Publisher"
  }

  # The two function apps. They are separate apps on purpose: separate identity, separate storage, separate blast radius.
  apps = merge(
    {
      sync = {
        label     = "kvsync"
        queue     = "kvsync-events"
        events    = ["Microsoft.KeyVault.CertificateNewVersionCreated", "Microsoft.KeyVault.CertificateNearExpiry"]
        source    = var.function_source.sync
        has_table = false
      }
    },
    var.enable_renew_app ? {
      renew = {
        label     = "kvrenew"
        queue     = "kvrenew-events"
        events    = ["Microsoft.KeyVault.CertificateNearExpiry"]
        source    = var.function_source.renew
        has_table = true
      }
    } : {}
  )

  tags = merge({ "managed-by" = "terraform", "workload" = "kv-cert-sync" }, var.tags)
}

# ------------------------------------------------------------------ monitoring
resource "azurerm_log_analytics_workspace" "this" {
  name                = "log-kvsync-${var.suffix}"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  tags                = local.tags
}

resource "azurerm_application_insights" "this" {
  name                         = "appi-kvsync-${var.suffix}"
  location                     = var.location
  resource_group_name          = var.resource_group_name
  workspace_id                 = azurerm_log_analytics_workspace.this.id
  application_type             = "web"
  local_authentication_enabled = false # telemetry is written with Entra ID, not with the instrumentation key
  internet_ingestion_enabled   = true
  internet_query_enabled       = true
  tags                         = local.tags
}

# ------------------------------------------------------------------ identities
resource "azurerm_user_assigned_identity" "app" {
  for_each            = local.apps
  name                = "uami-${each.value.label}-${var.suffix}"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = local.tags
}

resource "azurerm_role_assignment" "app_insights_publisher" {
  for_each             = local.apps
  scope                = azurerm_application_insights.this.id
  role_definition_name = local.role_name.metrics_publisher
  principal_id         = azurerm_user_assigned_identity.app[each.key].principal_id
  principal_type       = "ServicePrincipal"
}

# ------------------------------------------------------------------ source (issuing) vault
resource "azurerm_key_vault" "source" {
  name                          = "kv-src-${var.suffix}"
  location                      = var.location
  resource_group_name           = var.resource_group_name
  tenant_id                     = local.tenant_id
  sku_name                      = "standard"
  rbac_authorization_enabled    = true
  soft_delete_retention_days    = 7
  purge_protection_enabled      = var.source_purge_protection_enabled
  public_network_access_enabled = local.public
  tags                          = local.tags

  dynamic "network_acls" {
    for_each = local.private ? [1] : []
    content {
      default_action = "Deny"
      bypass         = "AzureServices"
    }
  }
}

# Audit log of every data-plane call (who read which secret) for the source and every destination vault.
resource "azurerm_monitor_diagnostic_setting" "vault_audit" {
  for_each                   = merge({ source = azurerm_key_vault.source.id }, { for k, d in local.dest : k => d.id })
  name                       = "audit-to-log-analytics"
  target_resource_id         = each.value
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id

  enabled_log {
    category_group = "audit"
  }
}
