data "azurerm_client_config" "hub" {}

locals {
  tags = {
    purpose        = "kv-cert-sync-poc"
    owner          = var.owner_tag
    "delete-after" = var.delete_after
  }

  rg_name = {
    hub     = "rg-${var.name_prefix}-hub"
    spoke_a = "rg-${var.name_prefix}-spoke-a"
    spoke_b = "rg-${var.name_prefix}-spoke-b"
  }

  tenant_id = data.azurerm_client_config.hub.tenant_id
}

# ------------------------------------------------------------------ resource groups
resource "azurerm_resource_group" "hub" {
  name     = local.rg_name.hub
  location = var.hub_location
  tags     = local.tags
}

resource "azurerm_resource_group" "spoke_a" {
  provider = azurerm.spoke_a
  name     = local.rg_name.spoke_a
  location = var.spoke_a_location
  tags     = local.tags
}

resource "azurerm_resource_group" "spoke_b" {
  provider = azurerm.spoke_b
  name     = local.rg_name.spoke_b
  location = var.spoke_b_location
  tags     = local.tags
}

# ------------------------------------------------------------------ policy waivers (sandbox only)
# An exemption is an ARM resource addressed by the resource group id, so one provider can create all of them.
locals {
  rg_id = {
    hub     = azurerm_resource_group.hub.id
    spoke_a = azurerm_resource_group.spoke_a.id
    spoke_b = azurerm_resource_group.spoke_b.id
  }
}

resource "azurerm_resource_group_policy_exemption" "poc" {
  for_each = { for e in var.policy_exemptions : "${e.target}/${e.name}" => e }

  name                            = each.value.name
  resource_group_id               = local.rg_id[each.value.target]
  policy_assignment_id            = each.value.policy_assignment_id
  policy_definition_reference_ids = length(each.value.reference_ids) > 0 ? each.value.reference_ids : null
  exemption_category              = "Waiver"
  expires_on                      = each.value.expires_on
  display_name                    = "kv-cert-sync proof of concept: public endpoints"
  description                     = "Time-boxed. The proof of concept is driven from a workstation, so its vaults and storage need public endpoints. Production uses private endpoints and needs no waiver."
}

# Policy exemptions take a while to reach the policy engine. Resources are created after this pause.
resource "time_sleep" "policy" {
  count           = length(var.policy_exemptions) > 0 ? 1 : 0
  create_duration = var.policy_propagation_wait
  depends_on      = [azurerm_resource_group_policy_exemption.poc]
}

# ------------------------------------------------------------------ destination (consumer) vaults
# In real life these already exist and belong to the application teams. The proof of concept creates two to have something
# to copy into. They are RBAC vaults, like the source.
resource "azurerm_key_vault" "spoke_a" {
  provider = azurerm.spoke_a

  name                          = "kv-dst-a-${var.suffix}"
  location                      = azurerm_resource_group.spoke_a.location
  resource_group_name           = azurerm_resource_group.spoke_a.name
  tenant_id                     = local.tenant_id
  sku_name                      = "standard"
  rbac_authorization_enabled    = true
  soft_delete_retention_days    = 7
  purge_protection_enabled      = true # the landing-zone policy of this lab requires it; it is also the right default
  public_network_access_enabled = true # sandbox only
  tags                          = local.tags

  depends_on = [time_sleep.policy]
}

resource "azurerm_key_vault" "spoke_b" {
  provider = azurerm.spoke_b

  name                          = "kv-dst-b-${var.suffix}"
  location                      = azurerm_resource_group.spoke_b.location
  resource_group_name           = azurerm_resource_group.spoke_b.name
  tenant_id                     = local.tenant_id
  sku_name                      = "standard"
  rbac_authorization_enabled    = true
  soft_delete_retention_days    = 7
  purge_protection_enabled      = false # lets the proof of concept be removed completely (purge) after the test
  public_network_access_enabled = true  # sandbox only
  tags                          = local.tags

  depends_on = [time_sleep.policy]
}

# ------------------------------------------------------------------ the hub: source vault, two function apps, eventing
module "hub" {
  source = "../modules/hub"

  suffix              = var.suffix
  location            = var.hub_location
  resource_group_name = azurerm_resource_group.hub.name
  tags                = local.tags

  network_mode = "public"
  destinations = {
    a = { vault_id = azurerm_key_vault.spoke_a.id }
    b = { vault_id = azurerm_key_vault.spoke_b.id }
  }

  source_purge_protection_enabled = false # proof of concept only
  operator_object_id              = var.operator_object_id

  ca_provider    = "testca"
  renew_settings = var.renew_settings

  reconcile_schedule = var.reconcile_schedule
  renew_schedule     = var.renew_schedule

  function_source = {
    sync  = abspath("${path.module}/../../src/sync")
    renew = abspath("${path.module}/../../src/renew")
  }

  alert_email_addresses = var.alert_email_addresses

  depends_on = [time_sleep.policy]
}

# ------------------------------------------------------------------ private test CA (proof of concept only)
# Stands in for DigiCert so the whole request -> sign -> merge -> copy chain can be tested without buying a certificate.
# NOTE: the CA private key is part of the Terraform state. That is acceptable for a throw-away test CA and is why the
# production stack has no such resource: there the CA is DigiCert and its API key is created outside Terraform.
resource "tls_private_key" "testca" {
  algorithm = "RSA"
  rsa_bits  = 3072
}

resource "tls_self_signed_cert" "testca" {
  private_key_pem       = tls_private_key.testca.private_key_pem
  validity_period_hours = 24 * 365
  is_ca_certificate     = true
  allowed_uses          = ["cert_signing", "crl_signing"]

  subject {
    common_name  = "KV Cert Sync PoC Test Root CA"
    organization = "kv-cert-sync-poc (not a trusted CA)"
  }
}

# The operator's Key Vault Administrator assignment (made by the module) must have replicated before the secret is written.
resource "time_sleep" "operator_rbac" {
  create_duration = "75s"
  depends_on      = [module.hub]
}

resource "azurerm_key_vault_secret" "testca" {
  name         = "ca-testca-bundle"
  key_vault_id = module.hub.source_vault_id
  content_type = "application/json"
  value = jsonencode({
    ca_cert_pem = tls_self_signed_cert.testca.cert_pem
    ca_key_pem  = tls_private_key.testca.private_key_pem
  })

  depends_on = [time_sleep.operator_rbac]
}


# ------------------------------------------------------------------ optional consumer test: Application Gateway v2
# A real consumer of the synced certificate. Lives in the spoke B subscription, next to the vault it reads from, which is how a
# landing zone is laid out. Own resource group so `terraform destroy -target=module.app_gateway` (or enable_app_gateway = false)
# removes it without touching the proof of concept. Billed per hour.
resource "azurerm_resource_group" "agw" {
  count    = var.enable_app_gateway ? 1 : 0
  provider = azurerm.spoke_b

  name     = "rg-${var.name_prefix}-agw"
  location = var.spoke_b_location
  tags     = local.tags

  depends_on = [time_sleep.policy]
}

module "app_gateway" {
  count  = var.enable_app_gateway ? 1 : 0
  source = "../modules/app_gateway"

  providers = {
    azurerm = azurerm.spoke_b
  }

  suffix              = var.suffix
  location            = azurerm_resource_group.agw[0].location
  resource_group_name = azurerm_resource_group.agw[0].name
  tags                = local.tags

  key_vault_id     = azurerm_key_vault.spoke_b.id
  key_vault_uri    = azurerm_key_vault.spoke_b.vault_uri
  certificate_name = var.app_gateway_certificate_name
}
