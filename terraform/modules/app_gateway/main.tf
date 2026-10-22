# A consumer of the synced certificate: an Application Gateway v2 that terminates TLS with a certificate stored in
# the consumer's OWN vault. It reads the certificate through a Key Vault reference by its user-assigned managed identity.
#
# Facts this module relies on (Microsoft Learn, "TLS termination with Key Vault certificates"):
#   - the secret id is bound WITHOUT a version, so the gateway picks up a new version on its own (it polls about every 4 hours);
#   - Application Gateway v2 only, user-assigned managed identity only;
#   - the identity needs read access to the secret (Key Vault Secrets User), and the certificate must be exportable.

locals {
  secret_id_versionless = "${trimsuffix(var.key_vault_uri, "/")}/secrets/${var.certificate_name}"
  names = {
    fe_ip    = "fe-public"
    fe_port  = "fe-443"
    pool     = "be-pool"
    settings = "be-https"
    probe    = "be-probe"
    listener = "https-listener"
    rule     = "https-rule"
    cert     = "kv-cert"
  }
}

resource "azurerm_user_assigned_identity" "agw" {
  name                = "uami-agw-${var.suffix}"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags
}

# Least privilege: read ONE secret, not the vault.
resource "azurerm_role_assignment" "agw_secret_reader" {
  scope                = "${var.key_vault_id}/secrets/${var.certificate_name}"
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.agw.principal_id
  principal_type       = "ServicePrincipal"
  description          = "Application Gateway reads the TLS certificate (PFX) by reference."
}

resource "time_sleep" "rbac" {
  create_duration = "60s"
  depends_on      = [azurerm_role_assignment.agw_secret_reader]
}

resource "azurerm_network_security_group" "agw" {
  name                = "nsg-agw-${var.suffix}"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags

  # required by Application Gateway v2: the Azure control plane reaches the gateway on these ports
  security_rule {
    name                       = "AllowGatewayManager"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "65200-65535"
    source_address_prefix      = "GatewayManager"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowAzureLoadBalancer"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "AzureLoadBalancer"
    destination_address_prefix = "*"
  }

  dynamic "security_rule" {
    for_each = var.allow_internet_inbound ? [1] : []
    content {
      name                       = "AllowHttpsFromInternetTestOnly"
      priority                   = 120
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_range     = "443"
      source_address_prefix      = "Internet"
      destination_address_prefix = "*"
    }
  }
}

resource "azurerm_virtual_network" "agw" {
  name                = "vnet-agw-${var.suffix}"
  location            = var.location
  resource_group_name = var.resource_group_name
  address_space       = [var.address_space]
  tags                = var.tags
}

resource "azurerm_subnet" "agw" {
  name                 = "snet-agw"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.agw.name
  address_prefixes     = [var.address_space]
}

resource "azurerm_subnet_network_security_group_association" "agw" {
  subnet_id                 = azurerm_subnet.agw.id
  network_security_group_id = azurerm_network_security_group.agw.id
}

resource "azurerm_public_ip" "agw" {
  name                = "pip-agw-${var.suffix}"
  location            = var.location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"
  domain_name_label   = "agw-kvsync-${var.suffix}"
  tags                = var.tags

  lifecycle {
    # Some governance policies stamp ip_tags (for example FirstPartyUsage) on every public IP after it is created. Without this,
    # the next plan would see a difference that can only be fixed by REPLACING the address, and with it the gateway's frontend.
    ignore_changes = [ip_tags]
  }
}

resource "azurerm_application_gateway" "this" {
  name                = "agw-kvsync-${var.suffix}"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags

  sku {
    name     = "Standard_v2"
    tier     = "Standard_v2"
    capacity = var.capacity
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.agw.id]
  }

  gateway_ip_configuration {
    name      = "gwip"
    subnet_id = azurerm_subnet.agw.id
  }

  frontend_ip_configuration {
    name                 = local.names.fe_ip
    public_ip_address_id = azurerm_public_ip.agw.id
  }

  frontend_port {
    name = local.names.fe_port
    port = 443
  }

  ssl_certificate {
    name                = local.names.cert
    key_vault_secret_id = local.secret_id_versionless
  }

  ssl_policy {
    policy_type = "Predefined"
    policy_name = "AppGwSslPolicy20220101"
  }

  backend_address_pool {
    name  = local.names.pool
    fqdns = [var.backend_fqdn]
  }

  probe {
    name                                      = local.names.probe
    protocol                                  = "Https"
    path                                      = "/"
    interval                                  = 30
    timeout                                   = 30
    unhealthy_threshold                       = 3
    pick_host_name_from_backend_http_settings = true
  }

  backend_http_settings {
    name                                = local.names.settings
    cookie_based_affinity               = "Disabled"
    port                                = 443
    protocol                            = "Https"
    request_timeout                     = 30
    pick_host_name_from_backend_address = true
    probe_name                          = local.names.probe
  }

  http_listener {
    name                           = local.names.listener
    frontend_ip_configuration_name = local.names.fe_ip
    frontend_port_name             = local.names.fe_port
    protocol                       = "Https"
    ssl_certificate_name           = local.names.cert
  }

  request_routing_rule {
    name                       = local.names.rule
    rule_type                  = "Basic"
    priority                   = 100
    http_listener_name         = local.names.listener
    backend_address_pool_name  = local.names.pool
    backend_http_settings_name = local.names.settings
  }

  depends_on = [
    time_sleep.rbac,
    azurerm_subnet_network_security_group_association.agw,
  ]
}
