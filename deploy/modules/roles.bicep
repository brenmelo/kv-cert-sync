// The two custom roles of the factory. Role definitions live at subscription scope, so this module is deployed there.
//
//   KV Certificate Importer  sync identity, on each destination vault: read and import certificates, nothing else
//   KV Certificate Issuer    renew identity, on the source vault: read, create a pending version (CSR), merge the signed chain
//
// Mirrors the role definitions in terraform/modules/hub/roles.tf.
targetScope = 'subscription'

@minLength(3)
@maxLength(8)
@description('Short token that makes the role names unique in the tenant.')
param suffix string

@description('Subscriptions in which the importer role may be assigned: the hub subscription plus every subscription that holds a destination vault.')
param importerSubscriptionIds array

param createImporter bool = true
param createIssuer bool = true

resource importer 'Microsoft.Authorization/roleDefinitions@2022-04-01' = if (createImporter) {
  name: guid(subscription().id, 'kv-certificate-importer', suffix)
  properties: {
    roleName: 'KV Certificate Importer ${suffix}'
    description: 'Read certificates and import a certificate version into a Key Vault. Cannot delete, purge, back up, restore, or touch keys and secrets.'
    type: 'CustomRole'
    permissions: [
      {
        actions: []
        dataActions: [
          'Microsoft.KeyVault/vaults/certificates/read'
          'Microsoft.KeyVault/vaults/certificates/import/action'
        ]
        notActions: []
        notDataActions: []
      }
    ]
    assignableScopes: [for id in union([subscription().subscriptionId], importerSubscriptionIds): '/subscriptions/${id}']
  }
}

resource issuer 'Microsoft.Authorization/roleDefinitions@2022-04-01' = if (createIssuer) {
  name: guid(subscription().id, 'kv-certificate-issuer', suffix)
  properties: {
    roleName: 'KV Certificate Issuer ${suffix}'
    description: 'Read certificates, create a new pending certificate version (CSR) and merge the signed chain. Cannot read private keys, delete, purge, import or change policy of other objects.'
    type: 'CustomRole'
    permissions: [
      {
        actions: []
        dataActions: [
          'Microsoft.KeyVault/vaults/certificates/read'
          'Microsoft.KeyVault/vaults/certificates/create/action'
          'Microsoft.KeyVault/vaults/certificates/update/action'
        ]
        notActions: []
        notDataActions: []
      }
    ]
    assignableScopes: [
      subscription().id
    ]
  }
}

output importerRoleDefinitionId string = createImporter ? importer.id : ''
output issuerRoleDefinitionId string = createIssuer ? issuer.id : ''
