# One provider per subscription. The subscription id is ALWAYS set explicitly, so a stray `az account set` can never move a
# deployment into another subscription.
#
# resource_provider_registrations = "none": the provider will not register resource providers behind your back. The
# subscriptions must already have these registered (az provider show -n <name> --query registrationState):
#   Microsoft.KeyVault, Microsoft.Storage, Microsoft.Web, Microsoft.App, Microsoft.EventGrid, Microsoft.ManagedIdentity,
#   Microsoft.OperationalInsights, Microsoft.Insights, Microsoft.Authorization, Microsoft.Network (App Gateway only)

provider "azurerm" {
  subscription_id                 = var.hub_subscription_id
  tenant_id                       = var.tenant_id
  resource_provider_registrations = "none"
  storage_use_azuread             = true

  features {
    key_vault {
      # A purge-protected vault cannot be purged anyway, and a PoC must not silently resurrect or purge vaults.
      purge_soft_delete_on_destroy    = false
      recover_soft_deleted_key_vaults = false
    }
  }
}

provider "azurerm" {
  alias                           = "spoke_a"
  subscription_id                 = var.spoke_a_subscription_id
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

provider "azurerm" {
  alias                           = "spoke_b"
  subscription_id                 = var.spoke_b_subscription_id
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