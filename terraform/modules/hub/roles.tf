# Least privilege, explained in docs/DESIGN-QA.md.
#
#   sync identity   source vault        Key Vault Certificate User, ABAC-limited so that it can never read the CA credential (ca-*)
#                                       (read certificate + its private key, nothing else)
#                   each destination    KV Certificate Importer    (read + import certificates, nothing else)
#   renew identity  source vault        KV Certificate Issuer      (read, create a new pending version, merge the chain)
#                                       Key Vault Secrets User, ABAC-limited to secrets named <ca_secret_name_prefix>*
#                   its own storage     Storage Table Data Contributor (renewal state)
#   Event Grid      each queue          Storage Queue Data Message Sender (identity-based delivery)

resource "azurerm_role_definition" "importer" {
  count       = var.destination_role_mode == "custom" ? 1 : 0
  name        = "KV Certificate Importer ${var.suffix}"
  scope       = "/subscriptions/${local.sub_id}"
  description = "Read certificates and import a certificate version into a Key Vault. Cannot delete, purge, back up, restore, or touch keys and secrets."

  permissions {
    actions = []
    data_actions = [
      "Microsoft.KeyVault/vaults/certificates/read",
      "Microsoft.KeyVault/vaults/certificates/import/action",
    ]
    not_actions      = []
    not_data_actions = []
  }

  assignable_scopes = local.role_scopes
}

resource "azurerm_role_definition" "issuer" {
  count       = var.enable_renew_app ? 1 : 0
  name        = "KV Certificate Issuer ${var.suffix}"
  scope       = "/subscriptions/${local.sub_id}"
  description = "Read certificates, create a new pending certificate version (CSR) and merge the signed chain. Cannot read private keys, delete, purge, import or change policy of other objects."

  permissions {
    actions = []
    data_actions = [
      "Microsoft.KeyVault/vaults/certificates/read",
      "Microsoft.KeyVault/vaults/certificates/create/action",
      "Microsoft.KeyVault/vaults/certificates/update/action",
    ]
    not_actions      = []
    not_data_actions = []
  }

  assignable_scopes = ["/subscriptions/${local.sub_id}"]
}

locals {
  secret_name_attr = "@Resource[Microsoft.KeyVault/vaults/secrets:name]"
  get_secret       = "ActionMatches{'Microsoft.KeyVault/vaults/secrets/getSecret/action'}"

  # The renewal identity may read only the CA credential (ca-*).
  ca_secret_condition = "((!(${local.get_secret})) OR (${local.secret_name_attr} StringStartsWith '${var.ca_secret_name_prefix}'))"

  # The sync identity must never read the CA credential. With sync_secret_name_prefix set it is stricter still: it may read only
  # the private key of certificates under that prefix. Without it, everything except ca-* is readable (a certificate's private key
  # is the secret that carries the certificate's name, so reading "a certificate" and reading "its secret" are the same call).
  sync_secret_condition = var.sync_secret_name_prefix == "" ? (
    "((!(${local.get_secret})) OR (${local.secret_name_attr} StringNotStartsWith '${var.ca_secret_name_prefix}'))"
    ) : (
    "((!(${local.get_secret})) OR (${local.secret_name_attr} StringStartsWith '${var.sync_secret_name_prefix}'))"
  )
}

# ---- source vault
resource "azurerm_role_assignment" "sync_on_source" {
  scope                = azurerm_key_vault.source.id
  role_definition_name = local.role_name.cert_user
  principal_id         = azurerm_user_assigned_identity.app["sync"].principal_id
  principal_type       = "ServicePrincipal"
  condition_version    = "2.0"
  condition            = local.sync_secret_condition
}

resource "azurerm_role_assignment" "renew_issuer_on_source" {
  count                = var.enable_renew_app ? 1 : 0
  scope                = azurerm_key_vault.source.id
  role_definition_name = azurerm_role_definition.issuer[0].name
  principal_id         = azurerm_user_assigned_identity.app["renew"].principal_id
  principal_type       = "ServicePrincipal"
}

resource "azurerm_role_assignment" "renew_ca_secret_on_source" {
  count                = var.enable_renew_app ? 1 : 0
  scope                = azurerm_key_vault.source.id
  role_definition_name = local.role_name.secrets_user
  principal_id         = azurerm_user_assigned_identity.app["renew"].principal_id
  principal_type       = "ServicePrincipal"
  condition_version    = "2.0"
  condition            = local.ca_secret_condition
}

# ---- destination vaults (any subscription)
resource "azurerm_role_assignment" "sync_on_destination" {
  for_each             = local.dest
  scope                = each.value.id
  role_definition_name = var.destination_role_mode == "custom" ? azurerm_role_definition.importer[0].name : local.role_name.cert_officer
  principal_id         = azurerm_user_assigned_identity.app["sync"].principal_id
  principal_type       = "ServicePrincipal"
}

# ---- test operator (proof of concept only)
resource "azurerm_role_assignment" "operator_on_source" {
  count                = var.operator_object_id == "" ? 0 : 1
  scope                = azurerm_key_vault.source.id
  role_definition_name = local.role_name.kv_admin
  principal_id         = var.operator_object_id
  principal_type       = "User"
}

resource "azurerm_role_assignment" "operator_on_destination" {
  for_each             = var.operator_object_id == "" ? {} : local.dest
  scope                = each.value.id
  role_definition_name = local.role_name.kv_admin
  principal_id         = var.operator_object_id
  principal_type       = "User"
}

# Lets the test operator peek at the event queues and read the renewal state table (proof of concept only).
resource "azurerm_role_assignment" "operator_queue_reader" {
  for_each             = var.operator_object_id == "" ? {} : local.apps
  scope                = azurerm_storage_account.app[each.key].id
  role_definition_name = "Storage Queue Data Reader"
  principal_id         = var.operator_object_id
  principal_type       = "User"
}

resource "azurerm_role_assignment" "operator_table_reader" {
  for_each             = var.operator_object_id == "" ? {} : { for k, a in local.apps : k => a if a.has_table }
  scope                = azurerm_storage_account.app[each.key].id
  role_definition_name = "Storage Table Data Reader"
  principal_id         = var.operator_object_id
  principal_type       = "User"
}