output "source_vault_uri" {
  value = module.hub.source_vault_uri
}

output "function_apps" {
  value = module.hub.function_apps
}

output "identities" {
  value = module.hub.identities
}

output "log_analytics_customer_id" {
  value = module.hub.log_analytics_customer_id
}

output "next_steps" {
  description = "What is NOT done by Terraform on purpose."
  value       = <<-EOT
    1. Put the CA API key in the source vault as a secret named ca-digicert-api-key. Do it from a machine that can reach the private endpoint:
         az keyvault secret set --vault-name ${module.hub.source_vault_name} --name ca-digicert-api-key --file <key-file>
       The renewal identity can read only secrets whose name starts with "ca-" (ABAC condition on its role assignment).
    2. Tag each certificate that must be copied:  kvsync=all  (or a comma separated list of destination keys).
       Tag each certificate that must be renewed automatically: kvrenew=on
    3. Run the first reconcile by hand and read the KVSYNC / KVRENEW lines in Log Analytics (workspace ${module.hub.log_analytics_customer_id}).
  EOT
}
