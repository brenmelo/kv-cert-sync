variable "hub_subscription_id" {
  type        = string
  description = "Subscription that hosts the source (issuing) vault, the two function apps and their storage."
}

variable "tenant_id" {
  type = string
}

variable "location" {
  type        = string
  description = "Region of the hub. Choose a region with availability zones; the destination vaults can be anywhere."
}

variable "resource_group_name" {
  type        = string
  description = "EXISTING resource group in the hub subscription."
}

variable "suffix" {
  type        = string
  description = "3-8 lower-case letters or digits that make the globally unique names unique."
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "destination_vault_ids" {
  type        = map(string)
  description = "Key => resource id of each EXISTING destination (consumer) vault, any subscription in the tenant. Example: { prod_eu = \"/subscriptions/.../resourceGroups/.../providers/Microsoft.KeyVault/vaults/kv-prod-eu\" }"
}

variable "private_endpoint_subnet_id" {
  type        = string
  description = "Subnet that receives the private endpoints (vault, storage, function apps)."
}

variable "function_subnet_ids" {
  type = object({
    sync  = string
    renew = string
  })
  description = "Two subnets delegated to Microsoft.App/environments, one per function app, for VNet integration."
}

variable "private_dns_zone_ids" {
  type = object({
    vault = optional(string)
    blob  = optional(string)
    queue = optional(string)
    table = optional(string)
    sites = optional(string)
  })
  default     = {}
  description = "Existing private DNS zones. Leave a zone null when a central Azure Policy (DeployIfNotExists) registers the DNS records for you."
}

variable "ca_provider" {
  type    = string
  default = "digicert"
}

variable "digicert_settings" {
  type        = map(string)
  default     = {}
  description = "Non-secret DigiCert settings for the renewal function, e.g. DIGICERT_PRODUCT, DIGICERT_ORGANIZATION_ID, DIGICERT_CONTAINER_ID, DIGICERT_ORDER_YEARS, DIGICERT_CERT_VALIDITY_DAYS, DIGICERT_DCV_METHOD. The API key is NOT a setting: it is a secret named ca-digicert-api-key in the source vault."
}

variable "enable_renew_app" {
  type    = bool
  default = true
}

variable "destination_role_mode" {
  type    = string
  default = "custom"
}

variable "sync_secret_name_prefix" {
  type    = string
  default = ""
}

variable "reconcile_schedule" {
  type    = string
  default = "0 */15 * * * *"
}

variable "renew_schedule" {
  type    = string
  default = "0 */15 * * * *"
}

variable "storage_replication_type" {
  type    = string
  default = "ZRS"
}

variable "log_retention_days" {
  type    = number
  default = 90
}

variable "alert_email_addresses" {
  type        = list(string)
  description = "At least one receiver: failed renewals and expiring certificates must reach a human."
  validation {
    condition     = length(var.alert_email_addresses) > 0
    error_message = "Provide at least one alert receiver."
  }
}

variable "key_vault_dns_suffix" {
  type    = string
  default = "vault.azure.net"
}
