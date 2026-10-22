# The subscription id is ALWAYS set explicitly, so a stray `az account set` can never move a deployment.
# Register these resource providers beforehand: Microsoft.KeyVault, Microsoft.Storage, Microsoft.Web, Microsoft.App,
# Microsoft.EventGrid, Microsoft.ManagedIdentity, Microsoft.OperationalInsights, Microsoft.Insights, Microsoft.Authorization,
# Microsoft.Network.

provider "azurerm" {
  subscription_id                 = var.hub_subscription_id
  tenant_id                       = var.tenant_id
  resource_provider_registrations = "none"
  storage_use_azuread             = true

  features {
    key_vault {
      purge_soft_delete_on_destroy    = false
      recover_soft_deleted_key_vaults = false
    }
  }
}


# AzAPI writes the function apps (see modules/hub/apps.tf). Resource ids are fully qualified, so this provider can reach any
# subscription; the id below only fixes the default so nothing depends on `az account set`.
provider "azapi" {
  subscription_id            = var.hub_subscription_id
  tenant_id                  = var.tenant_id
  skip_provider_registration = true
}