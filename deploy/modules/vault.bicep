// A destination (consumer) Key Vault for the proof of concept. In real life these vaults already exist and belong to the
// application teams; the proof of concept creates some to have something to copy into. RBAC vault, like the source.
targetScope = 'resourceGroup'

param name string
param location string = resourceGroup().location
param tags object = {}

@description('Purge protection. Some landing-zone policies require it. Once on it cannot be turned off, and the vault name stays reserved after deletion.')
param purgeProtection bool = false

@description('Sandbox only: public endpoint. Production uses private endpoints.')
param publicNetworkAccess string = 'Enabled'

resource vault 'Microsoft.KeyVault/vaults@2024-11-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    tenantId: tenant().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    enablePurgeProtection: purgeProtection ? true : null // can only be set to true, never to false
    publicNetworkAccess: publicNetworkAccess
  }
}

output id string = vault.id
output name string = vault.name
output vaultUri string = vault.properties.vaultUri
