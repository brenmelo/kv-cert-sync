// Key Vault certificate factory: PRODUCTION (resource group scope).
//
//   * the factory in the resource group you deploy to: source (issuing) vault, Event Grid, two function apps, monitoring, alerts
//   * every data-plane path is private: no public access to the vaults, the storage accounts or the function apps, private
//     endpoints, VNet-integrated function apps, purge protection, zone-redundant storage
//   * the two least-privilege custom roles, and the role assignments on your EXISTING destination vaults
//
// It is the ARM / Bicep twin of terraform/production. Nothing here creates a destination vault, a VNet, a subnet or a private DNS
// zone: those belong to your landing zone, and their ids are the inputs. deploy/production/examples/landing-zone.bicep builds a
// minimal one, to try this template in an empty subscription.
//
// The destination vaults can be in ANY subscription of the tenant. The identity that runs this deployment needs:
//   * Owner (or Contributor + User Access Administrator) on the resource group you deploy to,
//   * Owner or User Access Administrator on every destination vault (it assigns a role on each),
//   * Contributor on every destination vault when enableDestinationAudit is true (it adds a diagnostic setting),
//   * permission to create custom roles at subscription scope (Owner or User Access Administrator).
//
// Deploy to Azure button and the command line: see README.md. Nothing here can put the CA API key in the vault, on purpose:
// read the nextSteps output.
targetScope = 'resourceGroup'

@minLength(3)
@maxLength(8)
@description('Short lower-case token (3-8 letters or digits) that makes the global names unique (key vault, storage accounts, function apps).')
param suffix string

@description('Region of the factory. Choose a region with availability zones that supports Flex Consumption. The destination vaults can be anywhere.')
param location string = resourceGroup().location

@description('Tags for every resource the template creates.')
param tags object = {}

@description('EXISTING destination (consumer) vaults, any subscription of the tenant: { "<key>": "<vault resource id>" }. The key is a short label (no spaces, no commas) that a certificate tag can name: kvsync=<key> copies to that vault only, kvsync=all copies to every vault.')
param destinationVaultIds object

@description('Resource id of the subnet that receives the private endpoints (source vault, the two storage accounts, the two function apps).')
param privateEndpointSubnetId string

@description('Resource id of a subnet delegated to Microsoft.App/environments, for the VNet integration of the sync function app. Do not share it with the renewal app.')
param syncFunctionSubnetId string

@description('Resource id of a second subnet delegated to Microsoft.App/environments, for the VNet integration of the renewal function app.')
param renewFunctionSubnetId string

@description('Existing private DNS zone privatelink.vaultcore.azure.net. Leave empty when a central Azure Policy registers the DNS records of private endpoints.')
param vaultPrivateDnsZoneId string = ''

@description('Existing private DNS zone privatelink.blob.core.windows.net. Leave empty when a central policy registers the DNS records.')
param blobPrivateDnsZoneId string = ''

@description('Existing private DNS zone privatelink.queue.core.windows.net. Leave empty when a central policy registers the DNS records.')
param queuePrivateDnsZoneId string = ''

@description('Existing private DNS zone privatelink.table.core.windows.net. Leave empty when a central policy registers the DNS records.')
param tablePrivateDnsZoneId string = ''

@description('Existing private DNS zone privatelink.azurewebsites.net. Leave empty when a central policy registers the DNS records.')
param sitesPrivateDnsZoneId string = ''

@minLength(1)
@description('Receivers of the alert rules (failed renewal, failed copy, a stopped function app, a copy that is about to expire). At least one: these signals must reach a human.')
param alertEmailAddresses array

@allowed([
  'digicert'
  'testca'
])
@description('digicert = DigiCert CertCentral API (production). testca = a private test CA kept in the source vault: ONLY to try this template, never for real certificates.')
param caProvider string = 'digicert'

@description('Non-secret settings of the renewal function, for example { "DIGICERT_PRODUCT": "<CertCentral product name_id>", "DIGICERT_ORGANIZATION_ID": "123456", "DIGICERT_DCV_METHOD": "dns-txt-token" }. DIGICERT_PRODUCT is required for digicert. The API key is NOT a setting: it is the secret ca-digicert-api-key in the source vault.')
param renewSettings object = {}

@description('Deploy the renewal function. Without it only the replication (kvsync) runs and certificates are issued by something else.')
param enableRenewApp bool = true

@allowed([
  'custom'
  'builtin'
])
@description('custom = least-privilege role "KV Certificate Importer" on each destination vault (read + import certificates). builtin = Key Vault Certificates Officer (more than needed: it can also delete, purge, back up and restore).')
param destinationRoleMode string = 'custom'

@description('Optional (ABAC). When set, the sync identity can read the private key only of certificates whose name starts with this prefix. When empty it can read every secret of the source vault except ca-*.')
param syncSecretNamePrefix string = ''

@description('NCRONTAB of the sync safety-net sweep.')
param reconcileSchedule string = '0 */15 * * * *'

@description('NCRONTAB of the renewal sweep (starts renewals that are due and polls pending orders).')
param renewSchedule string = '0 */15 * * * *'

@allowed([
  'Standard_LRS'
  'Standard_ZRS'
  'Standard_GRS'
  'Standard_GZRS'
])
@description('Replication of the two storage accounts. ZRS keeps the function apps running through the loss of a zone.')
param storageSkuName string = 'Standard_ZRS'

@description('Retention of the Log Analytics workspace (30-730 days).')
@minValue(30)
@maxValue(730)
param logRetentionDays int = 90

@description('Write the data-plane audit log of every destination vault to the hub workspace (who read or wrote which certificate). It adds a diagnostic setting to each destination vault, which needs Contributor or Monitoring Contributor there; switch it off when you may only assign roles.')
param enableDestinationAudit bool = true

@description('DNS suffix of Key Vault in this cloud, with the leading dot (.vault.azure.net in Azure public). It turns a vault name into its address.')
param keyVaultDnsSuffix string = environment().suffixes.keyvaultDns

@description('Folder URL that holds sync/released-package.zip and renew/released-package.zip. Pin it to a release tag or a commit for a reproducible deployment, or host the two packages yourself.')
param packageBaseUri string = 'https://raw.githubusercontent.com/brenmelo/kv-cert-sync/main/deploy/packages'

@description('Deploy the code of both apps from packageBaseUri during this deployment. Set it to false to publish the code yourself afterwards (see docs/OPERATIONS.md), for example when the apps accept no connection from the Functions service.')
param deployCode bool = true

// Destination vaults: { key, vaultId, subscriptionId, resourceGroup, name, uri } parsed from the resource ids.
var destinationList = [for d in items(destinationVaultIds): {
  key: d.key
  vaultId: d.value
  subscriptionId: split(d.value, '/')[2]
  resourceGroup: split(d.value, '/')[4]
  name: split(d.value, '/')[8]
  uri: 'https://${split(d.value, '/')[8]}${keyVaultDnsSuffix}'
}]

var privateDnsZoneIds = {
  vault: vaultPrivateDnsZoneId
  blob: blobPrivateDnsZoneId
  queue: queuePrivateDnsZoneId
  table: tablePrivateDnsZoneId
  sites: sitesPrivateDnsZoneId
}

// ------------------------------------------------------------------ custom roles (subscription scope)
module roles '../modules/roles.bicep' = {
  name: 'kvsync-roles-${suffix}'
  scope: subscription()
  params: {
    suffix: suffix
    importerSubscriptionIds: map(destinationList, d => d.subscriptionId)
    createImporter: destinationRoleMode == 'custom'
    createIssuer: enableRenewApp
  }
}

// ------------------------------------------------------------------ the factory
module hub '../modules/hub.bicep' = {
  name: 'kvsync-hub-${suffix}'
  params: {
    suffix: suffix
    location: location
    tags: tags
    networkMode: 'private'
    destinations: map(destinationList, d => {
      key: d.key
      uri: d.uri
    })
    sourcePurgeProtection: true
    operatorObjectId: '' // nobody has standing data-plane access to the source vault
    enableRenewApp: enableRenewApp
    caProvider: caProvider
    syncSecretNamePrefix: syncSecretNamePrefix
    renewSettings: renewSettings
    reconcileSchedule: reconcileSchedule
    renewSchedule: renewSchedule
    packageBaseUri: packageBaseUri
    deployCode: deployCode
    storageSkuName: storageSkuName
    logRetentionDays: logRetentionDays
    alertEmailAddresses: alertEmailAddresses
    issuerRoleDefinitionId: roles.outputs.issuerRoleDefinitionId
    privateEndpointSubnetId: privateEndpointSubnetId
    functionSubnetIds: {
      sync: syncFunctionSubnetId
      renew: renewFunctionSubnetId
    }
    privateDnsZoneIds: privateDnsZoneIds
  }
}

// ------------------------------------------------------------------ access to the existing destination vaults
module access '../modules/destination-access.bicep' = [for d in destinationList: {
  name: 'kvsync-access-${suffix}-${uniqueString(d.vaultId)}'
  scope: resourceGroup(d.subscriptionId, d.resourceGroup)
  params: {
    vaultName: d.name
    syncPrincipalId: hub.outputs.syncPrincipalId
    syncIdentityId: hub.outputs.syncIdentityId
    destinationRoleMode: destinationRoleMode
    importerRoleDefinitionId: roles.outputs.importerRoleDefinitionId
    workspaceId: hub.outputs.workspaceId
    enableAudit: enableDestinationAudit
    auditSettingName: 'kvsync-audit-${suffix}'
  }
}]

// ------------------------------------------------------------------ outputs
output sourceVault object = hub.outputs.sourceVault
output functionApps object = hub.outputs.functionApps
output identities object = hub.outputs.identities
output queues object = hub.outputs.queues
output logAnalyticsCustomerId string = hub.outputs.logAnalyticsCustomerId

output roleDefinitions object = {
  importer: roles.outputs.importerRoleDefinitionId
  issuer: roles.outputs.issuerRoleDefinitionId
}

output destinationVaults array = [for d in destinationList: {
  key: d.key
  uri: d.uri
  subscription: d.subscriptionId
  resourceGroup: d.resourceGroup
}]

@description('What this deployment does NOT do on purpose.')
output nextSteps string = join([
  '1. Put the CA credential in the source vault as a secret whose name starts with "ca-". Do it from a machine that can reach the vault private endpoint, with a role that may write secrets (nobody has one by default):'
  '     az keyvault secret set --vault-name ${hub.outputs.sourceVault.name} --name ca-digicert-api-key --file <key-file>'
  '   The renewal identity can read only secrets whose name starts with "ca-" (an ABAC condition on its role assignment); the sync identity can never read them.'
  '2. Tag each certificate that must be copied: kvsync=all (or a comma-separated list of destination keys). Tag each certificate that must be renewed automatically: kvrenew=on.'
  '3. ${deployCode ? 'The code of both apps was deployed by this template.' : 'deployCode was false: publish the code of both apps yourself (docs/OPERATIONS.md) before anything runs.'}'
  '4. Read the KVSYNC and KVRENEW lines in Log Analytics (workspace ${hub.outputs.logAnalyticsCustomerId}). A healthy factory logs "reconcile-complete" at every sweep.'
], '\n')
