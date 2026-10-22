output "tenant_id" {
  value = local.tenant_id
}

output "resource_groups" {
  value = local.rg_name
}

output "source_vault" {
  value = {
    id           = module.hub.source_vault_id
    name         = module.hub.source_vault_name
    uri          = module.hub.source_vault_uri
    subscription = var.hub_subscription_id
  }
}

output "destination_vaults" {
  value = {
    a = {
      id           = azurerm_key_vault.spoke_a.id
      name         = azurerm_key_vault.spoke_a.name
      uri          = azurerm_key_vault.spoke_a.vault_uri
      subscription = var.spoke_a_subscription_id
    }
    b = {
      id           = azurerm_key_vault.spoke_b.id
      name         = azurerm_key_vault.spoke_b.name
      uri          = azurerm_key_vault.spoke_b.vault_uri
      subscription = var.spoke_b_subscription_id
    }
  }
}

output "function_apps" {
  value = module.hub.function_apps
}

output "identities" {
  value = module.hub.identities
}

output "queues" {
  value = module.hub.queues
}

output "log_analytics_customer_id" {
  value = module.hub.log_analytics_customer_id
}

output "role_definitions" {
  value = module.hub.role_definitions
}

output "event_grid_system_topic" {
  value = module.hub.event_grid_system_topic
}

output "app_gateway" {
  value = length(module.app_gateway) == 0 ? null : {
    name            = module.app_gateway[0].gateway_name
    fqdn            = module.app_gateway[0].fqdn
    public_ip       = module.app_gateway[0].public_ip
    secret_id_bound = module.app_gateway[0].secret_id_bound
    resource_group  = azurerm_resource_group.agw[0].name
    subscription    = var.spoke_b_subscription_id
  }
}
