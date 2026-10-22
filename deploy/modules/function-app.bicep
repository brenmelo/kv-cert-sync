// One event-driven Azure Functions app with everything it owns, in the hub resource group:
//
//   * a user-assigned managed identity (the app's only credential),
//   * a storage account that only that identity can use (Entra ID only, no account key),
//   * the queue that receives the Key Vault events, and, for the renewal app, its state table,
//   * Event Grid delivery into that queue (send-only, with the managed identity of the Event Grid system topic),
//   * the identity's roles on the source vault,
//   * a Flex Consumption plan (Linux, Python 3.12) and the function app,
//   * its code, deployed from a package URL with the "OneDeploy" extension (a remote build installs requirements.txt).
//
// Two instances of this module make the factory: kvsync (copies certificates) and kvrenew (requests / renews them at the CA).
// They are separate apps on purpose: separate identity, separate storage, separate blast radius.
// Mirrors terraform/modules/hub/apps.tf, eventing.tf and roles.tf.
targetScope = 'resourceGroup'

@minLength(3)
@maxLength(8)
@description('Short token that makes global names unique.')
param suffix string

param location string = resourceGroup().location
param tags object = {}

@minLength(1)
@maxLength(10)
@description('Short name used in resource names: kvsync or kvrenew.')
param label string

@description('Queue that receives the Key Vault events for this app.')
param queueName string

@description('Create the renewal-state table (kvrenew only).')
param hasTable bool = false

@description('Name of the app setting that carries the client id of this app identity (KVSYNC_CLIENT_ID or KVRENEW_CLIENT_ID).')
param clientIdSettingName string

@description('App settings that are specific to this app.')
param extraSettings object = {}

@description('Application Insights component in this resource group.')
param appInsightsName string

@description('Source (issuing) vault in this resource group.')
param sourceVaultName string

@description('Roles of this app identity on the source vault: [{ roleDefinitionId, condition }]. The condition (ABAC) may be empty.')
param sourceVaultRoles array = []

@description('Event Grid system topic of the source vault, in this resource group.')
param eventTopicName string

@description('Principal id of the system topic identity. It gets SEND-ONLY access to this app queue.')
param eventTopicPrincipalId string

@description('Key Vault event types that are delivered to this app.')
param includedEventTypes array

@description('URL of the code package (a zip named released-package.zip). The Functions service downloads it.')
param packageUri string

param maxInstanceCount int = 40

@allowed([
  'Standard_LRS'
  'Standard_ZRS'
  'Standard_GRS'
  'Standard_GZRS'
])
param storageSkuName string = 'Standard_LRS'

@allowed([
  'public'
  'private'
])
@description('public = public endpoints (proof of concept). private = no public data-plane access, private endpoints, VNet integration.')
param networkMode string = 'public'

param privateEndpointSubnetId string = ''

@description('private mode: subnet delegated to Microsoft.App/environments for the VNet integration of this app.')
param functionSubnetId string = ''

@description('private mode: private DNS zone ids { blob, queue, table, sites }. Leave a value empty when a central policy registers the DNS records.')
param privateDnsZoneIds object = {}

@description('TEST ONLY. A human who may peek at the event queue and read the renewal state table. Leave empty in production.')
param operatorObjectId string = ''

param operatorPrincipalType string = 'User'

var isPrivate = networkMode == 'private'
var siteName = 'func-${label}-${suffix}'
var identityName = 'uami-${label}-${suffix}'
var storageName = 'st${label}${suffix}'
var planName = 'plan-${label}-${suffix}'
var containerName = 'app-package-${siteName}'
var storageSuffix = environment().suffixes.storage

var roleIds = {
  blobOwner: 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b' // Storage Blob Data Owner
  queueContributor: '974c5e8b-45b9-4653-ba55-5f855dd0fb88' // Storage Queue Data Contributor
  tableContributor: '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3' // Storage Table Data Contributor
  metricsPublisher: '3913510d-42f4-4e42-8a64-420c390055eb' // Monitoring Metrics Publisher
  queueSender: 'c6a89b2d-59bc-44d0-9896-0f6e12d7b80a' // Storage Queue Data Message Sender
  queueReader: '19e7f393-937e-4f77-808e-94535e297925' // Storage Queue Data Reader
  tableReader: '76199698-9eea-4c19-bc75-cec21354c6b6' // Storage Table Data Reader
}

// ------------------------------------------------------------------ identity
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: identityName
  location: location
  tags: tags
}

// ------------------------------------------------------------------ storage
resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: {
    name: storageSkuName
  }
  properties: {
    accessTier: 'Hot'
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false // Entra ID only: no account key exists to leak
    defaultToOAuthAuthentication: true
    // private mode: only private endpoints and trusted Azure services (Event Grid, with its managed identity) get in
    networkAcls: isPrivate ? {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
    } : null
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
}

resource deployContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: containerName
  properties: {
    publicAccess: 'None'
  }
}

resource queueService 'Microsoft.Storage/storageAccounts/queueServices@2023-05-01' = {
  parent: storage
  name: 'default'
}

resource eventQueue 'Microsoft.Storage/storageAccounts/queueServices/queues@2023-05-01' = {
  parent: queueService
  name: queueName
}

resource tableService 'Microsoft.Storage/storageAccounts/tableServices@2023-05-01' = if (hasTable) {
  parent: storage
  name: 'default'
}

resource stateTable 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-05-01' = if (hasTable) {
  parent: tableService
  name: 'kvrenew'
}

// The roles the identity needs on its OWN storage account: Functions host state, queue trigger, renewal state table.
resource blobOwner 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, identity.id, roleIds.blobOwner)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.blobOwner)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource queueContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, identity.id, roleIds.queueContributor)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.queueContributor)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource tableContributor 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, identity.id, roleIds.tableContributor)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.tableContributor)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// ------------------------------------------------------------------ telemetry
resource appInsights 'Microsoft.Insights/components@2020-02-02' existing = {
  name: appInsightsName
}

resource metricsPublisher 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(appInsights.id, identity.id, roleIds.metricsPublisher)
  scope: appInsights
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.metricsPublisher)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// ------------------------------------------------------------------ source vault
resource sourceVault 'Microsoft.KeyVault/vaults@2024-11-01' existing = {
  name: sourceVaultName
}

// What this identity may do in the source vault (least privilege; see docs/DESIGN-QA.md).
resource sourceVaultAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for role in sourceVaultRoles: {
  name: guid(sourceVault.id, identity.id, role.roleDefinitionId)
  scope: sourceVault
  properties: {
    roleDefinitionId: role.roleDefinitionId
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
    condition: empty(role.condition) ? null : role.condition
    conditionVersion: empty(role.condition) ? null : '2.0'
  }
}]

// ------------------------------------------------------------------ hosting
resource plan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: planName
  location: location
  tags: tags
  kind: 'functionapp'
  sku: {
    name: 'FC1'
    tier: 'FlexConsumption'
  }
  properties: {
    reserved: true // Linux
  }
}

var baseSettings = {
  AzureWebJobsStorage__accountName: storage.name
  AzureWebJobsStorage__credential: 'managedidentity'
  AzureWebJobsStorage__clientId: identity.properties.clientId
  // The connection string only names the ingestion endpoint; with local authentication disabled it cannot write anything without Entra ID.
  APPLICATIONINSIGHTS_CONNECTION_STRING: appInsights.properties.ConnectionString
  APPLICATIONINSIGHTS_AUTHENTICATION_STRING: 'ClientId=${identity.properties.clientId};Authorization=AAD'
  INGEST_MODE: 'queue'
  QueueConn__queueServiceUri: 'https://${storage.name}.queue.${storageSuffix}'
  QueueConn__credential: 'managedidentity'
  QueueConn__clientId: identity.properties.clientId
  SOURCE_VAULT_URI: sourceVault.properties.vaultUri
}

var stateSettings = hasTable ? {
  STATE_TABLE_ENDPOINT: 'https://${storage.name}.table.${storageSuffix}'
  STATE_TABLE_NAME: 'kvrenew'
} : {}

var clientIdSetting = {
  '${clientIdSettingName}': identity.properties.clientId
}

var allSettings = union(baseSettings, stateSettings, clientIdSetting, extraSettings)

// Every setting stays visible in this file; nothing is added behind your back.
var appSettings = map(items(allSettings), item => {
  name: item.key
  value: item.value
})

resource site 'Microsoft.Web/sites@2024-04-01' = {
  name: siteName
  location: location
  tags: tags
  kind: 'functionapp,linux'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identity.id}': {}
    }
  }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    publicNetworkAccess: isPrivate ? 'Disabled' : 'Enabled' // private mode: reachable only through its private endpoint
    virtualNetworkSubnetId: isPrivate ? functionSubnetId : null
    siteConfig: {
      minTlsVersion: '1.2'
      http20Enabled: true
      ftpsState: 'Disabled'
      appSettings: appSettings
    }
    functionAppConfig: {
      deployment: {
        storage: {
          type: 'blobContainer'
          value: '${storage.properties.primaryEndpoints.blob}${containerName}'
          authentication: {
            type: 'UserAssignedIdentity'
            userAssignedIdentityResourceId: identity.id
          }
        }
      }
      scaleAndConcurrency: {
        maximumInstanceCount: maxInstanceCount
        instanceMemoryMB: 2048
      }
      runtime: {
        name: 'python'
        version: '3.12'
      }
    }
  }
  dependsOn: [
    // The platform uses the identity to reach the deployment container, so the roles must exist before the app is created.
    blobOwner
    queueContributor
    tableContributor
    metricsPublisher
    deployContainer
    eventQueue
  ]
}

// Code: the Functions service downloads the package and runs a remote build (pip install -r requirements.txt).
// The package must be named released-package.zip. Flex Consumption does not use WEBSITE_RUN_FROM_PACKAGE.
resource oneDeploy 'Microsoft.Web/sites/extensions@2022-09-01' = {
  parent: site
  name: 'onedeploy'
  #disable-next-line BCP187
  properties: {
    packageUri: packageUri
    remoteBuild: true
  }
  dependsOn: [
    sourceVaultAccess // the code starts only after the identity has its roles on the source vault
  ]
}

// No publishing passwords: neither FTP nor the Kudu (SCM) site accepts basic authentication. They are switched off after the
// code is deployed, so the deployment itself never depends on them.
resource ftpPolicy 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2024-04-01' = {
  parent: site
  name: 'ftp'
  properties: {
    allow: false
  }
  dependsOn: [
    oneDeploy
  ]
}

resource scmPolicy 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2024-04-01' = {
  parent: site
  name: 'scm'
  properties: {
    allow: false
  }
  dependsOn: [
    oneDeploy
  ]
}

// ------------------------------------------------------------------ events: Key Vault -> Event Grid -> this app's queue
// Event Grid writes each Key Vault certificate event into a queue that belongs to the app, and the app pulls from it. Compared
// with pushing to a function endpoint this works when the app has no public endpoint, keeps events for up to 7 days while the app
// is down, and authenticates with managed identities only. Events are a speed-up, not the guarantee: both apps also sweep on a
// timer, which is why there is no dead-letter destination.
resource topic 'Microsoft.EventGrid/systemTopics@2022-06-15' existing = {
  name: eventTopicName
}

// SEND-ONLY, and it must be assigned on the storage ACCOUNT: Event Grid validates delivery rights at account scope and rejects
// a subscription whose identity holds the role only on the queue.
resource queueSender 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, topic.id, roleIds.queueSender)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.queueSender)
    principalId: eventTopicPrincipalId
    principalType: 'ServicePrincipal'
  }
}

// Created after the code is deployed, which also gives the role assignment above time to replicate before Event Grid uses it.
resource eventSubscription 'Microsoft.EventGrid/systemTopics/eventSubscriptions@2022-06-15' = {
  parent: topic
  name: 'evgs-${label}-${suffix}'
  properties: {
    deliveryWithResourceIdentity: {
      identity: {
        type: 'SystemAssigned'
      }
      destination: {
        endpointType: 'StorageQueue'
        properties: {
          resourceId: storage.id
          queueName: queueName
          queueMessageTimeToLiveInSeconds: 604800
        }
      }
    }
    eventDeliverySchema: 'EventGridSchema'
    filter: {
      includedEventTypes: includedEventTypes
    }
    retryPolicy: {
      maxDeliveryAttempts: 30
      eventTimeToLiveInMinutes: 1440
    }
  }
  dependsOn: [
    queueSender
    eventQueue
    oneDeploy
  ]
}

// ------------------------------------------------------------------ test operator (proof of concept only)
resource operatorQueueReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(operatorObjectId)) {
  name: guid(storage.id, operatorObjectId, roleIds.queueReader)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.queueReader)
    principalId: operatorObjectId
    principalType: operatorPrincipalType
  }
}

resource operatorTableReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(operatorObjectId) && hasTable) {
  name: guid(storage.id, operatorObjectId, roleIds.tableReader)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.tableReader)
    principalId: operatorObjectId
    principalType: operatorPrincipalType
  }
}

// ------------------------------------------------------------------ private endpoints (private mode)
module peBlob 'private-endpoint.bicep' = if (isPrivate) {
  name: 'pe-blob-${label}-${suffix}'
  params: {
    name: 'pe-blob-${label}-${suffix}'
    location: location
    tags: tags
    subnetId: privateEndpointSubnetId
    targetResourceId: storage.id
    groupId: 'blob'
    dnsZoneId: privateDnsZoneIds.?blob ?? ''
  }
}

module peQueue 'private-endpoint.bicep' = if (isPrivate) {
  name: 'pe-queue-${label}-${suffix}'
  params: {
    name: 'pe-queue-${label}-${suffix}'
    location: location
    tags: tags
    subnetId: privateEndpointSubnetId
    targetResourceId: storage.id
    groupId: 'queue'
    dnsZoneId: privateDnsZoneIds.?queue ?? ''
  }
}

module peTable 'private-endpoint.bicep' = if (isPrivate && hasTable) {
  name: 'pe-table-${label}-${suffix}'
  params: {
    name: 'pe-table-${label}-${suffix}'
    location: location
    tags: tags
    subnetId: privateEndpointSubnetId
    targetResourceId: storage.id
    groupId: 'table'
    dnsZoneId: privateDnsZoneIds.?table ?? ''
  }
}

// Management plane of the function app (deployment, Kudu). There is no HTTP trigger to protect.
module peSites 'private-endpoint.bicep' = if (isPrivate) {
  name: 'pe-sites-${label}-${suffix}'
  params: {
    name: 'pe-sites-${label}-${suffix}'
    location: location
    tags: tags
    subnetId: privateEndpointSubnetId
    targetResourceId: site.id
    groupId: 'sites'
    dnsZoneId: privateDnsZoneIds.?sites ?? ''
  }
}

output identityName string = identity.name
output identityId string = identity.id
output clientId string = identity.properties.clientId
output principalId string = identity.properties.principalId
output storageAccountName string = storage.name
output siteName string = site.name
output defaultHostName string = site.properties.defaultHostName
output queueName string = eventQueue.name
