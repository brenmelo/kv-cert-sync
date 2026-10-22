variable "suffix" {
  type        = string
  description = "Short lower-case token (3-8 chars, letters and digits) that makes global names unique."
  validation {
    condition     = can(regex("^[a-z0-9]{3,8}$", var.suffix))
    error_message = "suffix must be 3-8 lower-case letters or digits."
  }
}

variable "location" {
  type        = string
  description = "Region of the hub resources (function apps, source vault, storage)."
}

variable "resource_group_name" {
  type        = string
  description = "Existing resource group in the hub subscription that receives the hub resources."
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "network_mode" {
  type        = string
  default     = "public"
  description = "public = public endpoints with Azure RBAC (proof of concept). private = no public data-plane access, private endpoints, VNet-integrated function apps (production)."
  validation {
    condition     = contains(["public", "private"], var.network_mode)
    error_message = "network_mode must be public or private."
  }
}

variable "destinations" {
  type = map(object({
    vault_id = string
  }))
  description = "Destination (consumer) vaults, keyed by a short name. Any subscription in the tenant. The vaults must already exist; this module only grants access to them."
}

variable "key_vault_dns_suffix" {
  type        = string
  default     = "vault.azure.net"
  description = "DNS suffix of Key Vault in the target cloud (vault.usgovcloudapi.net for Azure Government)."
}

variable "source_purge_protection_enabled" {
  type        = bool
  default     = true
  description = "Purge protection on the source (issuing) vault. Keep true outside a throw-away proof of concept: it cannot be switched off again."
}

variable "operator_object_id" {
  type        = string
  default     = ""
  description = "TEST ONLY. Object id of a human who gets Key Vault Administrator on the source and destination vaults so a test can create and inspect certificates. Leave empty in production."
}

variable "destination_role_mode" {
  type        = string
  default     = "custom"
  description = "custom = least-privilege 'KV Certificate Importer' (read + import certificates). builtin = built-in Key Vault Certificates Officer (more than needed: also delete, purge, backup, restore)."
  validation {
    condition     = contains(["custom", "builtin"], var.destination_role_mode)
    error_message = "destination_role_mode must be custom or builtin."
  }
}

variable "sync_secret_name_prefix" {
  type        = string
  default     = ""
  description = "Optional (ABAC). When set, the sync identity can read the private key only of certificates whose name starts with this prefix. When empty it can read every secret except those named <ca_secret_name_prefix>* (the CA credential)."
}

variable "ca_secret_name_prefix" {
  type        = string
  default     = "ca-"
  description = "The renewal identity can read only secrets whose name starts with this prefix (the CA API key / test CA bundle). Enforced with an ABAC condition."
}

variable "enable_renew_app" {
  type        = bool
  default     = true
  description = "Deploy the renewal function (request / reissue at the CA, merge the signed chain). Without it only the replication runs."
}

variable "ca_provider" {
  type        = string
  default     = "digicert"
  description = "digicert = DigiCert CertCentral API. testca = private test CA kept in the source vault (proof of concept only)."
  validation {
    condition     = contains(["digicert", "testca"], var.ca_provider)
    error_message = "ca_provider must be digicert or testca."
  }
}

variable "renew_settings" {
  type        = map(string)
  default     = {}
  description = "Extra app settings for the renewal function: RENEW_* tuning, TESTCA_* or DIGICERT_* settings (DIGICERT_PRODUCT is required for ca_provider = digicert)."
}

variable "sync_settings" {
  type        = map(string)
  default     = {}
  description = "Extra app settings for the sync function."
}

variable "reconcile_schedule" {
  type        = string
  default     = "0 */15 * * * *"
  description = "NCRONTAB of the sync safety-net sweep."
}

variable "renew_schedule" {
  type        = string
  default     = "0 */15 * * * *"
  description = "NCRONTAB of the renewal sweep (starts renewals that are due and polls pending orders)."
}

variable "function_source" {
  type = object({
    sync  = string
    renew = string
  })
  description = "Directories that contain the function apps (function_app.py, host.json, requirements.txt)."
}

variable "max_instance_count" {
  type    = number
  default = 40
}

variable "log_retention_days" {
  type    = number
  default = 30
}

variable "storage_replication_type" {
  type        = string
  default     = "LRS"
  description = "LRS for a proof of concept, ZRS (or GZRS) for production."
}

# ------------------------------------------------------------------ private mode
variable "private_endpoint_subnet_id" {
  type        = string
  default     = null
  description = "private mode: subnet that receives the private endpoints."
}

variable "function_subnet_ids" {
  type = object({
    sync  = string
    renew = string
  })
  default     = null
  description = "private mode: two subnets delegated to Microsoft.App/environments for VNet integration of the function apps (one per app)."
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
  description = "private mode: private DNS zones for the private endpoints (privatelink.vaultcore.azure.net, ...blob/queue/table.core.windows.net, privatelink.azurewebsites.net). Leave a zone null when a central policy registers the DNS records."
}

# ------------------------------------------------------------------ alerting
variable "alert_email_addresses" {
  type        = list(string)
  default     = []
  description = "Receivers of the alert rules. Empty = no alert rules are created."
}
