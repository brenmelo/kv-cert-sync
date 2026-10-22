# Private mode (production): no public data-plane access anywhere, traffic stays on the customer's network.
#
# This module creates the private endpoints of the hub resources. It does not create the VNet, the subnets or the private DNS
# zones: those belong to the customer's landing zone. Pass their ids in; leave a zone null when a central policy registers the
# DNS records for private endpoints.
#
# Destination vaults are owned by other teams and are not touched here. The sync function must be able to reach each of them:
# the destination vault needs a private endpoint that resolves and routes from the function subnet (usually already true in a
# hub-and-spoke landing zone), or its firewall must allow the function subnet / outbound addresses.

locals {
  pe_targets = local.private ? merge(
    {
      "vault-source" = {
        resource_id = azurerm_key_vault.source.id
        subresource = "vault"
        zone        = var.private_dns_zone_ids.vault
      }
    },
    {
      for pair in setproduct(keys(local.apps), ["blob", "queue"]) : "${pair[1]}-${pair[0]}" => {
        resource_id = azurerm_storage_account.app[pair[0]].id
        subresource = pair[1]
        zone        = pair[1] == "blob" ? var.private_dns_zone_ids.blob : var.private_dns_zone_ids.queue
      }
    },
    {
      for k, a in local.apps : "table-${k}" => {
        resource_id = azurerm_storage_account.app[k].id
        subresource = "table"
        zone        = var.private_dns_zone_ids.table
      } if a.has_table
    },
    {
      # management plane of the function app (deployment, Kudu). There is no HTTP trigger to protect.
      for k, a in local.apps : "sites-${k}" => {
        resource_id = azapi_resource.app[k].id
        subresource = "sites"
        zone        = var.private_dns_zone_ids.sites
      }
    },
  ) : {}
}

resource "azurerm_private_endpoint" "this" {
  for_each = local.pe_targets

  name                = "pe-${each.key}-${var.suffix}"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.private_endpoint_subnet_id
  tags                = local.tags

  private_service_connection {
    name                           = "psc-${each.key}"
    private_connection_resource_id = each.value.resource_id
    subresource_names              = [each.value.subresource]
    is_manual_connection           = false
  }

  dynamic "private_dns_zone_group" {
    for_each = each.value.zone == null ? [] : [each.value.zone]
    content {
      name                 = "default"
      private_dns_zone_ids = [private_dns_zone_group.value]
    }
  }
}

check "private_mode_inputs" {
  assert {
    condition     = var.network_mode == "public" || (var.private_endpoint_subnet_id != null && var.function_subnet_ids != null)
    error_message = "network_mode = private needs private_endpoint_subnet_id and function_subnet_ids."
  }
}
