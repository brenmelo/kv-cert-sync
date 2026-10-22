# Key Vault -> Event Grid -> Storage Queue -> function.
#
# Event Grid writes each Key Vault certificate event into a queue that belongs to the function app, and the function pulls from
# the queue. Compared with pushing to a function endpoint this
#   * works when the function app has no public endpoint (private mode),
#   * keeps events for up to 7 days when the function is down or throttled (a queue, not a retry budget),
#   * authenticates with managed identities only (Event Grid's system-assigned identity writes, the function's identity reads).
#
# Events are a speed-up, not the guarantee: both function apps also sweep on a timer and compare thumbprints, so an event that is
# lost (or never sent, e.g. a certificate imported while Event Grid was down) is repaired by the next sweep. That is why there is no
# dead-letter destination: it would need a second role (blob write) for Event Grid, and Event Grid cannot be limited to one container.

resource "azurerm_eventgrid_system_topic" "source" {
  name                = "evgt-kv-src-${var.suffix}"
  location            = var.location
  resource_group_name = var.resource_group_name
  source_resource_id  = azurerm_key_vault.source.id
  topic_type          = "Microsoft.KeyVault.vaults"
  tags                = local.tags

  identity {
    type = "SystemAssigned"
  }
}

# SEND-ONLY on the function app's storage account. It must be assigned on the ACCOUNT: Event Grid validates delivery rights at
# account scope and rejects a subscription whose identity only holds the role on the queue ("Managed Identity Authorization Error";
# verified: the same role on the account is accepted). The role cannot read or delete messages and cannot touch blobs or tables.
resource "azurerm_role_assignment" "eventgrid_queue_sender" {
  for_each             = local.apps
  scope                = azurerm_storage_account.app[each.key].id
  role_definition_name = local.role_name.queue_sender
  principal_id         = azurerm_eventgrid_system_topic.source.identity[0].principal_id
  principal_type       = "ServicePrincipal"
}

# Role assignments need a moment to replicate before Event Grid can use them.
resource "time_sleep" "eventgrid_rbac" {
  create_duration = "60s"
  depends_on      = [azurerm_role_assignment.eventgrid_queue_sender]
}

resource "azurerm_eventgrid_system_topic_event_subscription" "app" {
  for_each = local.apps

  name                  = "evgs-${each.value.label}-${var.suffix}"
  system_topic          = azurerm_eventgrid_system_topic.source.name
  resource_group_name   = var.resource_group_name
  event_delivery_schema = "EventGridSchema"
  included_event_types  = each.value.events

  delivery_identity {
    type = "SystemAssigned"
  }

  storage_queue_endpoint {
    storage_account_id                    = azurerm_storage_account.app[each.key].id
    queue_name                            = azurerm_storage_queue.events[each.key].name
    queue_message_time_to_live_in_seconds = 604800
  }

  retry_policy {
    max_delivery_attempts = 30
    event_time_to_live    = 1440
  }

  depends_on = [time_sleep.eventgrid_rbac, azurerm_storage_queue.events]
}