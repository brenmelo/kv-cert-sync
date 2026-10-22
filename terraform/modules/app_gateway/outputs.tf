output "gateway_id" {
  value = azurerm_application_gateway.this.id
}

output "gateway_name" {
  value = azurerm_application_gateway.this.name
}

output "public_ip" {
  value = azurerm_public_ip.agw.ip_address
}

output "fqdn" {
  value = azurerm_public_ip.agw.fqdn
}

output "identity" {
  value = {
    name         = azurerm_user_assigned_identity.agw.name
    principal_id = azurerm_user_assigned_identity.agw.principal_id
  }
}

output "secret_id_bound" {
  value       = local.secret_id_versionless
  description = "The versionless secret id the gateway is bound to."
}
