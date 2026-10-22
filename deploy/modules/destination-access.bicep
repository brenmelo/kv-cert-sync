// Access to ONE existing destination (consumer) vault, in the resource group of that vault, which may be in any subscription.
//
//   * the sync identity may read and import certificates there (a least-privilege custom role, or the built-in
//     Certificates Officer when destinationRoleMode = builtin),
//   * every data-plane call to the vault is written to the hub Log Analytics workspace (who read or wrote what),
//   * TEST ONLY: a human operator gets Key Vault Administrator so a test can create and inspect certificates.
//
// The vault itself is not created or changed. Mirrors the destination parts of terraform/modules/hub/roles.tf and main.tf.
targetScope = 'resourceGroup'

@description('Name of the existing destination vault (in this resource group).')
param vaultName string

@description('Principal id of the sync identity (output of the hub).')
param syncPrincipalId string

@description('Resource id of the sync identity. Used only to name the role assignment deterministically.')
param syncIdentityId string

@allowed([
  'custom'
  'builtin'
])
@description('custom = least-privilege "KV Certificate Importer" (read + import certificates). builtin = Key Vault Certificates Officer (more than needed: also delete, purge, backup, restore).')
param destinationRoleMode string = 'custom'

@description('Resource id of the custom role "KV Certificate Importer" (created by roles.bicep). Required when destinationRoleMode is custom.')
param importerRoleDefinitionId string = ''

@description('Log Analytics workspace that receives the vault audit log. It may be in another subscription and region.')
param workspaceId string

@description('TEST ONLY. Object id of a human who gets Key Vault Administrator on this vault. Leave empty in production.')
param operatorObjectId string = ''

@description('Principal type of operatorObjectId: User, Group or ServicePrincipal.')
param operatorPrincipalType string = 'User'

var certOfficerRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'a4417e6f-fecd-4de8-b567-7b0420556985') // Key Vault Certificates Officer
var adminRoleId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '00482a5a-887f-4fb3-b363-3b7fe8e74483') // Key Vault Administrator
var syncRoleDefinitionId = destinationRoleMode == 'custom' ? importerRoleDefinitionId : certOfficerRoleId

resource vault 'Microsoft.KeyVault/vaults@2024-11-01' existing = {
  name: vaultName
}

resource syncAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(vault.id, syncIdentityId, syncRoleDefinitionId)
  scope: vault
  properties: {
    roleDefinitionId: syncRoleDefinitionId
    principalId: syncPrincipalId
    principalType: 'ServicePrincipal'
  }
}

resource operatorAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(operatorObjectId)) {
  name: guid(vault.id, operatorObjectId, adminRoleId)
  scope: vault
  properties: {
    roleDefinitionId: adminRoleId
    principalId: operatorObjectId
    principalType: operatorPrincipalType
  }
}

resource audit 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'audit-to-log-analytics'
  scope: vault
  properties: {
    workspaceId: workspaceId
    logs: [
      {
        categoryGroup: 'audit'
        enabled: true
      }
    ]
  }
}

output vaultId string = vault.id
output vaultUri string = vault.properties.vaultUri
