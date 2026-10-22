terraform {
  required_version = ">= 1.9"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 5.10, < 6.0"
    }
    azapi = {
      source  = "Azure/azapi"
      version = ">= 2.8, < 3.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.7"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.13"
    }
  }

  # Production state belongs in a private storage account with Entra authentication, never in a local file:
  # the state of this stack contains resource ids and (for some resources) sensitive values.
  # Configure it at init time so no storage name is committed:
  #   terraform init -backend-config="resource_group_name=..." -backend-config="storage_account_name=..." \
  #                  -backend-config="container_name=tfstate" -backend-config="key=kv-cert-sync.tfstate"
  backend "azurerm" {
    use_azuread_auth = true
  }
}
