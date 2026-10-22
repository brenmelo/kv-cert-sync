output "source_vault_id" {
  value       = azurerm_key_vault.source.id
  description = "Resource id of the source (issuing) vault."
}

output "source_vault_name" {
  value = azurerm_key_vault.source.name
}

output "source_vault_uri" {
  value = azurerm_key_vault.source.vault_uri
}

output "function_apps" {
  description = "Function app names, by role (sync, renew)."
  value       = { for k, f in azapi_resource.app : k => f.name }
}

output "identities" {
  description = "Managed identities of the function apps. Grant these (and only these) access to new destination vaults."
  value = {
    for k, i in azurerm_user_assigned_identity.app : k => {
      name         = i.name
      client_id    = i.client_id
      principal_id = i.principal_id
    }
  }
}

output "queues" {
  description = "Event queues, by app."
  value       = { for k, q in azurerm_storage_queue.events : k => q.name }
}

output "function_app_hostnames" {
  description = "Default host names of the function apps (reachable only through the private endpoint in private mode)."
  value       = { for k, f in azapi_resource.app : k => f.output.properties.defaultHostName }
}

output "storage_accounts" {
  value = { for k, s in azurerm_storage_account.app : k => s.name }
}

output "event_grid_system_topic" {
  value = azurerm_eventgrid_system_topic.source.name
}

output "log_analytics_workspace_id" {
  value       = azurerm_log_analytics_workspace.this.id
  description = "Resource id; KVSYNC / KVRENEW lines are in the AppTraces table."
}

output "log_analytics_customer_id" {
  value       = azurerm_log_analytics_workspace.this.workspace_id
  description = "Workspace (customer) id, as used by 'az monitor log-analytics query --workspace'."
}

output "role_definitions" {
  value = {
    importer = try(azurerm_role_definition.importer[0].role_definition_resource_id, null)
    issuer   = try(azurerm_role_definition.issuer[0].role_definition_resource_id, null)
  }
}

output "destinations" {
  description = "Destination vaults as the sync function sees them."
  value       = local.dest
}

output "network_mode" {
  value = var.network_mode
}
