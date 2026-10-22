variable "hub_subscription_id" {
  type        = string
  description = "Subscription that hosts the source (issuing) vault and the function apps."
}

variable "spoke_a_subscription_id" {
  type        = string
  description = "Subscription of the first destination vault. May equal the hub subscription."
}

variable "spoke_b_subscription_id" {
  type        = string
  description = "Subscription of the second destination vault. May equal another subscription of the same tenant."
}

variable "tenant_id" {
  type        = string
  default     = null
  description = "Entra tenant. Leave null to use the tenant of the signed-in Azure CLI account."
}

variable "suffix" {
  type        = string
  description = "Short token (3-8 lower-case letters or digits) that makes the global names unique, e.g. a1b2c."
  validation {
    condition     = can(regex("^[a-z0-9]{3,8}$", var.suffix))
    error_message = "suffix must be 3-8 lower-case letters or digits."
  }
}

variable "name_prefix" {
  type        = string
  default     = "kvsync-tf"
  description = "Used in resource group names: rg-<name_prefix>-hub / -spoke-a / -spoke-b."
}

variable "hub_location" {
  type    = string
  default = "eastus2"
}

variable "spoke_a_location" {
  type    = string
  default = "westus3"
}

variable "spoke_b_location" {
  type    = string
  default = "northeurope"
}

variable "owner_tag" {
  type        = string
  description = "Value of the 'owner' tag."
}

variable "delete_after" {
  type        = string
  description = "Value of the 'delete-after' tag (a date, yyyy-mm-dd). The deployment is a throw-away proof of concept."
}

variable "operator_object_id" {
  type        = string
  description = "Object id of the person who runs the test. Gets Key Vault Administrator on all three vaults (TEST ONLY)."
}

variable "alert_email_addresses" {
  type    = list(string)
  default = []
}

# ------------------------------------------------------------------ test knobs
variable "reconcile_schedule" {
  type    = string
  default = "0 */5 * * * *"
}

variable "renew_schedule" {
  type    = string
  default = "0 */5 * * * *"
}

variable "renew_settings" {
  type = map(string)
  default = {
    # The test CA signs for 30 days after a 20 s simulated validation delay; renewals may follow each other immediately.
    TESTCA_DAYS              = "30"
    TESTCA_DELAY_SECONDS     = "20"
    RENEW_MIN_AGE_HOURS      = "0"
    RENEW_POLL_SECONDS       = "90"
    RENEW_DAYS_BEFORE_EXPIRY = "30"
  }
  description = "App settings of the renewal function (see docs/OPERATIONS.md)."
}

# ------------------------------------------------------------------ policy
variable "policy_exemptions" {
  type = list(object({
    name                 = string
    target               = string # hub | spoke_a | spoke_b : the resource group that receives the waiver
    policy_assignment_id = string
    reference_ids        = optional(list(string), [])
    expires_on           = string # RFC 3339, e.g. 2027-01-18T00:00:00Z
  }))
  default     = []
  description = <<-EOT
    Time-boxed policy WAIVERS for a sandbox whose policy forces public network access off, which the proof of concept
    needs (it runs from a workstation). Created BEFORE the resources. Empty list = no waiver (a subscription that allows
    public endpoints, or a run that uses network_mode = private). Production needs none.
  EOT
  validation {
    condition     = alltrue([for e in var.policy_exemptions : contains(["hub", "spoke_a", "spoke_b"], e.target)])
    error_message = "target must be hub, spoke_a or spoke_b."
  }
}

variable "policy_propagation_wait" {
  type        = string
  default     = "120s"
  description = "How long to wait after creating the waivers before creating resources."
}

# ------------------------------------------------------------------ optional consumer test
variable "enable_app_gateway" {
  type        = bool
  default     = false
  description = "Deploy an Application Gateway v2 (no WAF) in the spoke B subscription that serves the synced certificate from the spoke B vault. About 0.25 USD per hour: destroy it after the test."
}

variable "app_gateway_certificate_name" {
  type        = string
  default     = ""
  description = "Name of a certificate that already exists in the spoke B vault (it must have been synced there first). Required when enable_app_gateway is true."
  validation {
    condition     = var.app_gateway_certificate_name == "" || can(regex("^[0-9A-Za-z-]{1,127}$", var.app_gateway_certificate_name))
    error_message = "A Key Vault certificate name is 1-127 letters, digits or hyphens."
  }
  validation {
    condition     = !var.enable_app_gateway || var.app_gateway_certificate_name != ""
    error_message = "Set app_gateway_certificate_name to a certificate that has already been synced into the spoke B vault."
  }
}
