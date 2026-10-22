variable "suffix" {
  type = string
}

variable "location" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "key_vault_id" {
  type        = string
  description = "The CONSUMER's vault (a destination vault of the sync), in the same subscription as the gateway."
}

variable "key_vault_uri" {
  type        = string
  description = "Vault URI, e.g. https://kv-dst-b-x.vault.azure.net/"
}

variable "certificate_name" {
  type        = string
  description = "Name of the certificate in the consumer vault. The gateway binds the VERSIONLESS secret, so it picks up every new version."
}

variable "address_space" {
  type    = string
  default = "10.250.0.0/24"
}

variable "backend_fqdn" {
  type        = string
  default     = "learn.microsoft.com"
  description = "Any HTTPS site. The test only needs the listener to complete a TLS handshake with the synced certificate."
}

variable "capacity" {
  type    = number
  default = 1
}

variable "allow_internet_inbound" {
  type        = bool
  default     = true
  description = "Open 443 from the internet on the gateway subnet. Test only: production puts a WAF and the real client ranges here."
}
