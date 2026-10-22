// The certificate factory: everything that lives in the hub resource group.
//
//   source vault -> Event Grid system topic -> one Storage queue per function app -> function apps (kvsync, kvrenew)
//
//   kvsync   copies a certificate (with its private key) from the source vault into every destination vault
//   kvrenew  requests / reissues certificates at the CA and merges the signed chain into the source vault (optional)
//
// Access to the DESTINATION vaults is not granted here: they can live in any subscription, so a separate module
// (destination-access.bicep) is deployed into each destination resource group by the template that calls this one.
// Mirrors terraform/modules/hub.
targetScope = 'resourceGroup'

@minLength(3)
@maxLength(8)
@description('Short lower-case token (3-8 letters or digits) that makes the global names unique.')
param suffix string

param location string = resourceGroup().location
param tags object = {}

@allowed([
  'public'
  'private'
])
@description('public = public endpoints with Azure RBAC (proof of concept). private = no public data-plane access, private endpoints, VNet-integrated function apps (production).')
param networkMode string = 'public'

@description('Destination (consumer) vaults as [{ key, uri }]. Only their addresses are needed here.')
param destinations array = []

@description('Purge protection on the source (issuing) vault. Keep true outside a throw-away proof of concept: it cannot be switched off again.')
param sourcePurgeProtection bool = true

@description('TEST ONLY. Object id of a human who gets Key Vault Administrator on the source vault and can peek at the event queues. Leave empty in production.')
param operatorObjectId string = ''

@description('Principal type of operatorObjectId: User, Group or ServicePrincipal.')
param operatorPrincipalType string = 'User'

@description('Deploy the renewal function (request / reissue at the CA, merge the signed chain). Without it only the replication runs.')
param enableRenewApp bool = true

@allowed([
  'digicert'
  'testca'
])
@description('digicert = DigiCert CertCentral API. testca = private test CA kept in the source vault (proof of concept only).')
param caProvider string = 'digicert'

@description('The renewal identity can read only secrets whose name starts with this prefix (the CA API key or test CA bundle). Enforced with an ABAC condition.')
param caSecretNamePrefix string = 'ca-'

@description('Optional (ABAC). When set, the sync identity can read the private key only of certificates whose name starts with this prefix. When empty it can read every secret except those named <caSecretNamePrefix>*.')
param syncSecretNamePrefix string = ''

@description('Extra app settings for the sync function.')
param syncSettings object = {}

@description('Extra app settings for the renewal function: RENEW_*, TESTCA_* or DIGICERT_* settings (DIGICERT_PRODUCT is required for caProvider = digicert).')
param renewSettings object = {}

@description('NCRONTAB of the sync safety-net sweep.')
param reconcileSchedule string = '0 */15 * * * *'

@description('NCRONTAB of the renewal sweep (starts renewals that are due and polls pending orders).')
param renewSchedule string = '0 */15 * * * *'

@minLength(1)
@description('Folder URL that holds sync/released-package.zip and renew/released-package.zip. The Functions service downloads them.')
param packageBaseUri string

param maxInstanceCount int = 40
param logRetentionDays int = 30

@allowed([
  'Standard_LRS'
  'Standard_ZRS'
  'Standard_GRS'
  'Standard_GZRS'
])
@description('LRS for a proof of concept, ZRS for production.')
param storageSkuName string = 'Standard_LRS'

@description('Receivers of the alert rules. Empty = no alert rules are created.')
param alertEmailAddresses array = []

@description('Resource id of the custom role "KV Certificate Issuer" (created by roles.bicep). Required when enableRenewApp is true.')
param issuerRoleDefinitionId string = ''

@description('private mode: subnet that receives the private endpoints.')
param privateEndpointSubnetId string = ''

@description('private mode: { sync, renew } = two subnets delegated to Microsoft.App/environments for the VNet integration of the function apps.')
param functionSubnetIds object = {}

@description('private mode: private DNS zone ids { vault, blob, queue, table, sites }. Leave a value empty when a central policy registers the DNS records.')
param privateDnsZoneIds object = {}

var isPrivate = networkMode == 'private'
var alertsEnabled = !empty(alertEmailAddresses)
var baseUri = endsWith(packageBaseUri, '/') ? substring(packageBaseUri, 0, length(packageBaseUri) - 1) : packageBaseUri

var roleIds = {
  certUser: 'db79e9a7-68ee-4b58-9aeb-b90e7c24fcba' // Key Vault Certificate User
  secretsUser: '4633458b-17de-408a-b874-0445c86b69e6' // Key Vault Secrets User
  kvAdmin: '00482a5a-887f-4fb3-b363-3b7fe8e74483' // Key Vault Administrator
}

// ------------------------------------------------------------------ least privilege (explained in docs/DESIGN-QA.md)
//   sync identity   source vault   Key Vault Certificate User, ABAC-limited so that it can never read the CA credential (ca-*)
//   renew identity  source vault   KV Certificate Issuer (read, create a pending version, merge the chain)
//                                  Key Vault Secrets User, ABAC-limited to secrets named <caSecretNamePrefix>*
var secretNameAttr = '@Resource[Microsoft.KeyVault/vaults/secrets:name]'
var getSecret = 'ActionMatches{\'Microsoft.KeyVault/vaults/secrets/getSecret/action\'}'

// The renewal identity may read only the CA credential (ca-*).
var caSecretCondition = '((!(${getSecret})) OR (${secretNameAttr} StringStartsWith \'${caSecretNamePrefix}\'))'

// The sync identity must never read the CA credential. With syncSecretNamePrefix set it is stricter still: it may read only the
// private key of certificates under that prefix. A certificate's private key is the secret that carries the certificate's name,
// so reading "a certificate" and reading "its secret" are the same call.
var syncSecretCondition = empty(syncSecretNamePrefix)
  ? '((!(${getSecret})) OR (${secretNameAttr} StringNotStartsWith \'${caSecretNamePrefix}\'))'
  : '((!(${getSecret})) OR (${secretNameAttr} StringStartsWith \'${syncSecretNamePrefix}\'))'

var syncSourceRoles = [
  {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.certUser)
    condition: syncSecretCondition
  }
]

var renewSourceRoles = [
  {
    roleDefinitionId: issuerRoleDefinitionId
    condition: ''
  }
  {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.secretsUser)
    condition: caSecretCondition
  }
]

// ------------------------------------------------------------------ app settings of the two apps
var syncAppSettings = union({
  DEST_VAULTS_JSON: string(destinations)
  RECONCILE_SCHEDULE: reconcileSchedule
  SYNC_QUEUE_NAME: 'kvsync-events'
}, syncSettings)

var caSecretSetting = caProvider == 'testca' ? {
  TESTCA_SECRET_NAME: '${caSecretNamePrefix}testca-bundle'
} : {
  CA_SECRET_NAME: '${caSecretNamePrefix}digicert-api-key'
}

var renewAppSettings = union({
  CA_PROVIDER: caProvider
  RENEW_SCHEDULE: renewSchedule
  RENEW_QUEUE_NAME: 'kvrenew-events'
}, caSecretSetting, renewSettings)

// ------------------------------------------------------------------ monitoring
resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: 'log-kvsync-${suffix}'
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: logRetentionDays
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: 'appi-kvsync-${suffix}'
  location: location
  tags: tags
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: workspace.id
    DisableLocalAuth: true // telemetry is written with Entra ID, not with the instrumentation key
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

// ------------------------------------------------------------------ source (issuing) vault
resource sourceVault 'Microsoft.KeyVault/vaults@2024-11-01' = {
  name: 'kv-src-${suffix}'
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
    enablePurgeProtection: sourcePurgeProtection ? true : null // can only be set to true, never to false
    publicNetworkAccess: isPrivate ? 'Disabled' : 'Enabled'
    networkAcls: isPrivate ? {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
    } : null
  }
}

// Audit log of every data-plane call (who read which secret) for the source vault; the destination vaults are wired in
// destination-access.bicep.
resource sourceAudit 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'audit-to-log-analytics'
  scope: sourceVault
  properties: {
    workspaceId: workspace.id
    logs: [
      {
        categoryGroup: 'audit'
        enabled: true
      }
    ]
  }
}

resource operatorOnSource 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(operatorObjectId)) {
  name: guid(sourceVault.id, operatorObjectId, roleIds.kvAdmin)
  scope: sourceVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleIds.kvAdmin)
    principalId: operatorObjectId
    principalType: operatorPrincipalType
  }
}

module peVault 'private-endpoint.bicep' = if (isPrivate) {
  name: 'pe-vault-source-${suffix}'
  params: {
    name: 'pe-vault-source-${suffix}'
    location: location
    tags: tags
    subnetId: privateEndpointSubnetId
    targetResourceId: sourceVault.id
    groupId: 'vault'
    dnsZoneId: privateDnsZoneIds.?vault ?? ''
  }
}

// ------------------------------------------------------------------ eventing: Key Vault -> Event Grid
// The identity of the system topic is what writes into the apps' queues (send-only, assigned inside function-app.bicep).
resource topic 'Microsoft.EventGrid/systemTopics@2022-06-15' = {
  name: 'evgt-kv-src-${suffix}'
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    source: sourceVault.id
    topicType: 'Microsoft.KeyVault.vaults'
  }
}

// ------------------------------------------------------------------ the two function apps
module syncApp 'function-app.bicep' = {
  name: 'app-kvsync-${suffix}'
  params: {
    suffix: suffix
    location: location
    tags: tags
    label: 'kvsync'
    queueName: 'kvsync-events'
    clientIdSettingName: 'KVSYNC_CLIENT_ID'
    extraSettings: syncAppSettings
    appInsightsName: appInsights.name
    sourceVaultName: sourceVault.name
    sourceVaultRoles: syncSourceRoles
    eventTopicName: topic.name
    eventTopicPrincipalId: topic.identity.principalId
    includedEventTypes: [
      'Microsoft.KeyVault.CertificateNewVersionCreated'
      'Microsoft.KeyVault.CertificateNearExpiry'
    ]
    packageUri: '${baseUri}/sync/released-package.zip'
    maxInstanceCount: maxInstanceCount
    storageSkuName: storageSkuName
    networkMode: networkMode
    privateEndpointSubnetId: privateEndpointSubnetId
    functionSubnetId: functionSubnetIds.?sync ?? ''
    privateDnsZoneIds: privateDnsZoneIds
    operatorObjectId: operatorObjectId
    operatorPrincipalType: operatorPrincipalType
  }
}

module renewApp 'function-app.bicep' = if (enableRenewApp) {
  name: 'app-kvrenew-${suffix}'
  params: {
    suffix: suffix
    location: location
    tags: tags
    label: 'kvrenew'
    queueName: 'kvrenew-events'
    hasTable: true
    clientIdSettingName: 'KVRENEW_CLIENT_ID'
    extraSettings: renewAppSettings
    appInsightsName: appInsights.name
    sourceVaultName: sourceVault.name
    sourceVaultRoles: renewSourceRoles
    eventTopicName: topic.name
    eventTopicPrincipalId: topic.identity.principalId
    includedEventTypes: [
      'Microsoft.KeyVault.CertificateNearExpiry'
    ]
    packageUri: '${baseUri}/renew/released-package.zip'
    maxInstanceCount: maxInstanceCount
    storageSkuName: storageSkuName
    networkMode: networkMode
    privateEndpointSubnetId: privateEndpointSubnetId
    functionSubnetId: functionSubnetIds.?renew ?? ''
    privateDnsZoneIds: privateDnsZoneIds
    operatorObjectId: operatorObjectId
    operatorPrincipalType: operatorPrincipalType
  }
}

// ------------------------------------------------------------------ alerting (created only when alertEmailAddresses is not empty)
// Three independent signals, so one failing component cannot hide the others:
//   1. failures  - a function logged a permanent failure, a transient failure or a blocked renewal
//   2. heartbeat - a function app stopped running its timer sweep (it logs "reconcile-complete" every sweep)
//   3. replica   - the copy that applications use is close to expiry although it is up to date. This is the end-to-end check:
//                  whatever went wrong upstream (renewal, the CA, the tag, the copy), the certificate is going stale.
// Every rule is STATEFUL (autoMitigate): one notification when it fires and one when the condition clears.
resource actionGroup 'Microsoft.Insights/actionGroups@2023-01-01' = if (alertsEnabled) {
  name: 'ag-kvsync-${suffix}'
  location: 'global'
  tags: tags
  properties: {
    groupShortName: 'kvsync'
    enabled: true
    emailReceivers: [for (address, i) in alertEmailAddresses: {
      name: 'receiver-${i}'
      emailAddress: address
      useCommonAlertSchema: true
    }]
  }
}

resource alertFailures 'Microsoft.Insights/scheduledQueryRules@2023-12-01' = if (alertsEnabled) {
  name: 'alert-kvsync-failures-${suffix}'
  location: location
  tags: tags
  kind: 'LogAlert'
  properties: {
    displayName: 'Key Vault certificate sync/renew: failure'
    description: 'A KVSYNC or KVRENEW line reports a failed copy, a failed renewal, or a renewal blocked by the rate limit.'
    severity: 2
    enabled: true
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    scopes: [
      workspace.id
    ]
    autoMitigate: true
    criteria: {
      allOf: [
        {
          query: 'AppTraces\n| where Message contains "KVSYNC result=failed" or Message contains "KVRENEW result=failed" or Message contains "KVRENEW result=blocked"'
          timeAggregation: 'Count'
          operator: 'GreaterThanOrEqual'
          threshold: 1
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    actions: {
      actionGroups: [
        actionGroup.id
      ]
    }
  }
}

resource alertHeartbeatSync 'Microsoft.Insights/scheduledQueryRules@2023-12-01' = if (alertsEnabled) {
  name: 'alert-kvsync-heartbeat-${suffix}'
  location: location
  tags: tags
  kind: 'LogAlert'
  properties: {
    displayName: 'Key Vault certificate sync: no sweep in the last hour'
    description: 'The sync function app has not logged a completed timer sweep. The app is stopped, throttled, or cannot start.'
    severity: 2
    enabled: true
    evaluationFrequency: 'PT15M'
    windowSize: 'PT1H'
    scopes: [
      workspace.id
    ]
    autoMitigate: true
    criteria: {
      allOf: [
        {
          query: 'AppTraces\n| where Message contains "KVSYNC result=reconcile-complete"'
          timeAggregation: 'Count'
          operator: 'LessThan'
          threshold: 1
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    actions: {
      actionGroups: [
        actionGroup.id
      ]
    }
  }
}

resource alertHeartbeatRenew 'Microsoft.Insights/scheduledQueryRules@2023-12-01' = if (alertsEnabled && enableRenewApp) {
  name: 'alert-kvrenew-heartbeat-${suffix}'
  location: location
  tags: tags
  kind: 'LogAlert'
  properties: {
    displayName: 'Key Vault certificate renew: no sweep in the last hour'
    description: 'The renew function app has not logged a completed timer sweep. The app is stopped, throttled, or cannot start.'
    severity: 2
    enabled: true
    evaluationFrequency: 'PT15M'
    windowSize: 'PT1H'
    scopes: [
      workspace.id
    ]
    autoMitigate: true
    criteria: {
      allOf: [
        {
          query: 'AppTraces\n| where Message contains "KVRENEW result=reconcile-complete"'
          timeAggregation: 'Count'
          operator: 'LessThan'
          threshold: 1
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    actions: {
      actionGroups: [
        actionGroup.id
      ]
    }
  }
}

resource alertReplicaExpiring 'Microsoft.Insights/scheduledQueryRules@2023-12-01' = if (alertsEnabled && !empty(destinations)) {
  name: 'alert-kvsync-replica-expiring-${suffix}'
  location: location
  tags: tags
  kind: 'LogAlert'
  properties: {
    displayName: 'Key Vault certificate sync: a copy is about to expire'
    description: 'A certificate copy has fewer days left than REPLICA_WARN_DAYS (default 7), although the sync is up to date. A healthy chain renews and copies long before that, so renewal, the CA or the source tag is stuck.'
    severity: 1
    enabled: true
    evaluationFrequency: 'PT15M'
    windowSize: 'PT1H'
    scopes: [
      workspace.id
    ]
    autoMitigate: true
    criteria: {
      allOf: [
        {
          query: 'AppTraces\n| where Message contains "KVSYNC result=replica-expiring"'
          timeAggregation: 'Count'
          operator: 'GreaterThanOrEqual'
          threshold: 1
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    actions: {
      actionGroups: [
        actionGroup.id
      ]
    }
  }
}

// ------------------------------------------------------------------ outputs (same shapes as the Terraform module)
output sourceVault object = {
  id: sourceVault.id
  name: sourceVault.name
  uri: sourceVault.properties.vaultUri
}

output functionApps object = union({
  sync: syncApp.outputs.siteName
}, enableRenewApp ? {
  renew: renewApp.?outputs.siteName
} : {})

output identities object = union({
  sync: {
    name: syncApp.outputs.identityName
    client_id: syncApp.outputs.clientId
    principal_id: syncApp.outputs.principalId
  }
}, enableRenewApp ? {
  renew: {
    name: renewApp.?outputs.identityName
    client_id: renewApp.?outputs.clientId
    principal_id: renewApp.?outputs.principalId
  }
} : {})

output queues object = union({
  sync: syncApp.outputs.queueName
}, enableRenewApp ? {
  renew: renewApp.?outputs.queueName
} : {})

output syncIdentityId string = syncApp.outputs.identityId
output syncPrincipalId string = syncApp.outputs.principalId
output workspaceId string = workspace.id
output logAnalyticsCustomerId string = workspace.properties.customerId
output eventGridSystemTopic string = topic.name
