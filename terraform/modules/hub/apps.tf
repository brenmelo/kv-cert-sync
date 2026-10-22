# The function apps: one for replication (kvsync) and, optionally, one for renewal (kvrenew).
# Each app has its own identity, storage account, plan and code package, so a compromise of one does not give the other's access.

locals {
  func_name = { for k, a in local.apps : k => "func-${a.label}-${var.suffix}" }
  rg_id     = "/subscriptions/${local.sub_id}/resourceGroups/${var.resource_group_name}"

  # Storage roles the identity needs on its OWN storage account (Functions host state, queue trigger, renewal state table).
  storage_roles = {
    for pair in setproduct(keys(local.apps), ["blob_owner", "queue_contributor", "table_contributor"]) :
    "${pair[0]}-${pair[1]}" => { app = pair[0], role = pair[1] }
  }

  ca_secret_name = var.ca_provider == "testca" ? { "TESTCA_SECRET_NAME" = "${var.ca_secret_name_prefix}testca-bundle" } : { "CA_SECRET_NAME" = "${var.ca_secret_name_prefix}digicert-api-key" }

  app_settings = {
    for k, a in local.apps : k => merge(
      {
        "AzureWebJobsStorage__accountName" = azurerm_storage_account.app[k].name
        "AzureWebJobsStorage__credential"  = "managedidentity"
        "AzureWebJobsStorage__clientId"    = azurerm_user_assigned_identity.app[k].client_id
        # The connection string only names the ingestion endpoint; with local authentication disabled it cannot write anything without Entra ID.
        "APPLICATIONINSIGHTS_CONNECTION_STRING"     = nonsensitive(azurerm_application_insights.this.connection_string)
        "APPLICATIONINSIGHTS_AUTHENTICATION_STRING" = "ClientId=${azurerm_user_assigned_identity.app[k].client_id};Authorization=AAD"
        "INGEST_MODE"                               = "queue"
        "QueueConn__queueServiceUri"                = trimsuffix(azurerm_storage_account.app[k].primary_queue_endpoint, "/")
        "QueueConn__credential"                     = "managedidentity"
        "QueueConn__clientId"                       = azurerm_user_assigned_identity.app[k].client_id
        "SOURCE_VAULT_URI"                          = azurerm_key_vault.source.vault_uri
      },
      k == "sync" ? merge(
        {
          "KVSYNC_CLIENT_ID"   = azurerm_user_assigned_identity.app[k].client_id
          "DEST_VAULTS_JSON"   = local.dest_json
          "RECONCILE_SCHEDULE" = var.reconcile_schedule
          "SYNC_QUEUE_NAME"    = a.queue
        },
        var.sync_settings
      ) : {},
      k == "renew" ? merge(
        {
          "KVRENEW_CLIENT_ID"    = azurerm_user_assigned_identity.app[k].client_id
          "STATE_TABLE_ENDPOINT" = trimsuffix(azurerm_storage_account.app[k].primary_table_endpoint, "/")
          "STATE_TABLE_NAME"     = "kvrenew"
          "CA_PROVIDER"          = var.ca_provider
          "RENEW_SCHEDULE"       = var.renew_schedule
          "RENEW_QUEUE_NAME"     = a.queue
        },
        local.ca_secret_name,
        var.renew_settings
      ) : {},
    )
  }
}

# ------------------------------------------------------------------ storage
resource "azurerm_storage_account" "app" {
  for_each = local.apps

  name                            = "st${each.value.label}${var.suffix}"
  resource_group_name             = var.resource_group_name
  location                        = var.location
  account_kind                    = "StorageV2"
  account_tier                    = "Standard"
  account_replication_type        = var.storage_replication_type
  access_tier                     = "Hot"
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = false # Entra ID only: no account key exists to leak
  default_to_oauth_authentication = true
  tags                            = local.tags

  # Private mode: only private endpoints and trusted Azure services (Event Grid, with its managed identity) get in.
  dynamic "network_rules" {
    for_each = local.private ? [1] : []
    content {
      default_action = "Deny"
      bypass         = ["AzureServices"]
    }
  }
}

resource "azurerm_storage_container" "deploy" {
  for_each              = local.apps
  name                  = "app-package-${local.func_name[each.key]}"
  storage_account_id    = azurerm_storage_account.app[each.key].id
  container_access_type = "private"
}

resource "azurerm_storage_queue" "events" {
  for_each           = local.apps
  name               = each.value.queue
  storage_account_id = azurerm_storage_account.app[each.key].id
}

resource "azurerm_storage_table" "state" {
  for_each           = { for k, a in local.apps : k => a if a.has_table }
  name               = "kvrenew"
  storage_account_id = azurerm_storage_account.app[each.key].id
}

resource "azurerm_role_assignment" "app_storage" {
  for_each             = local.storage_roles
  scope                = azurerm_storage_account.app[each.value.app].id
  role_definition_name = local.role_name[each.value.role]
  principal_id         = azurerm_user_assigned_identity.app[each.value.app].principal_id
  principal_type       = "ServicePrincipal"
}

# Entra role assignments need a moment to replicate before the platform (which uses the identity to reach the deployment
# container) can rely on them. Cheaper than a failed first apply.
resource "time_sleep" "rbac" {
  create_duration = "60s"
  depends_on      = [azurerm_role_assignment.app_storage, azurerm_role_assignment.app_insights_publisher]
}

# ------------------------------------------------------------------ hosting
resource "azurerm_service_plan" "app" {
  for_each            = local.apps
  name                = "plan-${each.value.label}-${var.suffix}"
  resource_group_name = var.resource_group_name
  location            = var.location
  os_type             = "Linux"
  sku_name            = "FC1" # Flex Consumption
  tags                = local.tags
}

# Why AzAPI (the ARM API directly) and not azurerm_function_app_flex_consumption?
#
# With azurerm v5.10.0 the provider added a plain `AzureWebJobsStorage` app setting (built from its `storage_access_key` argument,
# which is empty here because the storage account has shared keys disabled) next to the identity-based
# `AzureWebJobsStorage__accountName` settings below. The Functions host prefers the plain setting, so no function started
# until that one setting was deleted by hand (observed in this proof of concept). Writing the ARM resource directly, as the Microsoft
# Learn templates do, keeps every setting visible in code and no setting is added behind your back. Everything else (plan,
# storage, identities, roles) stays on azurerm.
resource "azapi_resource" "app" {
  for_each = local.apps

  type      = "Microsoft.Web/sites@2024-04-01"
  name      = local.func_name[each.key]
  parent_id = local.rg_id
  location  = var.location
  tags      = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.app[each.key].id]
  }

  body = {
    kind = "functionapp,linux"
    properties = merge(
      {
        serverFarmId        = azurerm_service_plan.app[each.key].id
        httpsOnly           = true
        publicNetworkAccess = local.public ? "Enabled" : "Disabled" # private mode: reachable only through its private endpoint

        siteConfig = {
          minTlsVersion = "1.2"
          http20Enabled = true
          ftpsState     = "Disabled"
          appSettings   = [for name, value in local.app_settings[each.key] : { name = name, value = value }]
        }

        functionAppConfig = {
          deployment = {
            storage = {
              type  = "blobContainer"
              value = "${azurerm_storage_account.app[each.key].primary_blob_endpoint}${azurerm_storage_container.deploy[each.key].name}"
              authentication = {
                type                           = "UserAssignedIdentity"
                userAssignedIdentityResourceId = azurerm_user_assigned_identity.app[each.key].id
              }
            }
          }
          scaleAndConcurrency = {
            maximumInstanceCount = var.max_instance_count
            instanceMemoryMB     = 2048
          }
          runtime = {
            name    = "python"
            version = "3.12"
          }
        }
      },
      local.private ? { virtualNetworkSubnetId = var.function_subnet_ids[each.key] } : {}
    )
  }

  response_export_values = ["properties.defaultHostName"]

  # ARM returns the plan id as ".../serverfarms/..." while azurerm writes ".../serverFarms/...". Same resource; do not show a diff.
  ignore_casing = true

  depends_on = [time_sleep.rbac]
}

# No publishing passwords: neither FTP nor the Kudu (SCM) site accepts basic authentication. Code is deployed with Entra ID.
# These two policy objects exist on every site from the moment it is created, so they are updated in place
# (azapi_update_resource) rather than created.
resource "azapi_update_resource" "basic_auth_off" {
  for_each = {
    for pair in setproduct(keys(local.apps), ["ftp", "scm"]) : "${pair[0]}-${pair[1]}" => { app = pair[0], endpoint = pair[1] }
  }

  type      = "Microsoft.Web/sites/basicPublishingCredentialsPolicies@2024-04-01"
  name      = each.value.endpoint
  parent_id = azapi_resource.app[each.value.app].id
  body      = { properties = { allow = false } }
}

# ------------------------------------------------------------------ code
data "archive_file" "app" {
  for_each    = local.apps
  type        = "zip"
  source_dir  = each.value.source
  output_path = "${path.root}/.build/${each.value.label}.zip"
  excludes    = ["local.settings.json", ".funcignore", "**/__pycache__/**", "**/*.pyc", ".venv/**", "tests/**"]
}

# Zip deploy with Entra ID (no publishing password). The remote build installs requirements.txt on the service, so the package
# is the same on Windows, macOS and Linux. Re-runs when the code changes.
resource "terraform_data" "deploy" {
  for_each = local.apps

  triggers_replace = [
    data.archive_file.app[each.key].output_base64sha256,
    azapi_resource.app[each.key].id,
  ]

  provisioner "local-exec" {
    # The zip lives at ./.build/<app>.zip (relative to the root module, no spaces), so it must not be quoted: on Windows cmd.exe passes
    # the quote characters through to the Azure CLI as part of the file name.
    command = "az functionapp deployment source config-zip --resource-group ${var.resource_group_name} --name ${local.func_name[each.key]} --subscription ${local.sub_id} --src ${data.archive_file.app[each.key].output_path} --build-remote true --timeout 600"
  }

  depends_on = [
    azapi_update_resource.basic_auth_off,
    azurerm_role_assignment.sync_on_source,
    azurerm_role_assignment.sync_on_destination,
    azurerm_role_assignment.renew_issuer_on_source,
    azurerm_role_assignment.renew_ca_secret_on_source,
  ]
}
