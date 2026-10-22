// Key Vault certificate factory: the proof of concept as ONE deployment (subscription scope).
//
//   * a hub resource group with the factory: source vault, Event Grid, two function apps, monitoring, optional alerts
//   * two destination vaults (spoke A and spoke B) in their own resource groups, in any two subscriptions of the tenant
//   * the two least-privilege custom roles and the role assignments between all of it
//
// It is the ARM / Bicep twin of terraform/poc. Public endpoints with Azure RBAC, a private TEST CA instead of DigiCert, and no
// private networking: a throw-away sandbox. For production use deploy/production (or terraform/production).
//
// Deploy to Azure button: see README.md. Command line:
//   az deployment sub create --location <region> --template-file deploy/poc/main.bicep --parameters suffix=<3-8 chars>
//
// After the deployment, put the test CA into the source vault (ARM cannot generate keys): scripts/make_testca.py
targetScope = 'subscription'

@minLength(3)
@maxLength(8)
@description('Short lower-case token (3-8 letters or digits) that makes the global names unique. The default is stable per subscription, so a re-deployment updates the same resources.')
param suffix string = substring(uniqueString(subscription().id), 0, 5)

@description('Used in resource group names: rg-<namePrefix>-hub, -spoke-a and -spoke-b.')
param namePrefix string = 'kvsync-arm'

@description('Region of the hub resources (function apps, source vault, storage). It must support Flex Consumption.')
param hubLocation string = deployment().location

@description('Subscription of the first destination vault. May equal the hub subscription (the default). Any subscription of the same tenant works; you need Owner or User Access Administrator there.')
param spokeASubscriptionId string = subscription().subscriptionId

@description('Region of the first destination vault.')
param spokeALocation string = hubLocation

@description('Subscription of the second destination vault. May equal the hub subscription (the default).')
param spokeBSubscriptionId string = subscription().subscriptionId

@description('Region of the second destination vault.')
param spokeBLocation string = hubLocation

@description('Purge protection on destination vault A. Some landing-zone policies require it. Once on it cannot be turned off.')
param spokeAPurgeProtection bool = true

@description('Purge protection on destination vault B. Off lets the proof of concept be removed completely (purged) after the test.')
param spokeBPurgeProtection bool = false

@description('Value of the owner tag. Empty = no owner tag.')
param ownerTag string = ''

@description('Value of the delete-after tag (a date, yyyy-mm-dd). The deployment is a throw-away proof of concept.')
param deleteAfter string = dateTimeAdd(utcNow(), 'P30D', 'yyyy-MM-dd')

@description('Receivers of the alert rules. Empty = no alert rules are created.')
param alertEmailAddresses array = []

@description('TEST ONLY. Object id of the person who runs the test. Gets Key Vault Administrator on the three vaults and read access to the event queues. Defaults to whoever starts the deployment. Empty = nobody (set operatorPrincipalType to match when it is a service principal).')
param operatorObjectId string = deployer().objectId

@allowed([
  'User'
  'Group'
  'ServicePrincipal'
])
@description('Type of the principal in operatorObjectId. Use ServicePrincipal when a pipeline or an app registration deploys the template.')
param operatorPrincipalType string = 'User'

@description('Folder URL that holds sync/released-package.zip and renew/released-package.zip. Pin it to a tag or commit when you want a reproducible deployment.')
param packageBaseUri string = 'https://raw.githubusercontent.com/brenmelo/kv-cert-sync/main/deploy/packages'

@description('NCRONTAB of the sync safety-net sweep. Short, so the test is quick.')
param reconcileSchedule string = '0 */5 * * * *'

@description('NCRONTAB of the renewal sweep. Short, so the test is quick.')
param renewSchedule string = '0 */5 * * * *'

@description('App settings of the renewal function. The test CA signs for 30 days after a 20 s simulated validation delay; renewals may follow each other immediately.')
param renewSettings object = {
  TESTCA_DAYS: '30'
  TESTCA_DELAY_SECONDS: '20'
  RENEW_MIN_AGE_HOURS: '0'
  RENEW_POLL_SECONDS: '90'
  RENEW_DAYS_BEFORE_EXPIRY: '30'
}

var tags = union({
  purpose: 'kv-cert-sync-poc'
  'managed-by': 'arm'
  workload: 'kv-cert-sync'
  'delete-after': deleteAfter
}, empty(ownerTag) ? {} : {
  owner: ownerTag
})

var rgNames = {
  hub: 'rg-${namePrefix}-hub'
  spokeA: 'rg-${namePrefix}-spoke-a'
  spokeB: 'rg-${namePrefix}-spoke-b'
}

// ------------------------------------------------------------------ resource groups (each in its own subscription)
module rgHub '../modules/resource-group.bicep' = {
  name: 'kvsync-rg-hub-${suffix}'
  params: {
    name: rgNames.hub
    location: hubLocation
    tags: tags
  }
}

module rgA '../modules/resource-group.bicep' = {
  name: 'kvsync-rg-a-${suffix}'
  scope: subscription(spokeASubscriptionId)
  params: {
    name: rgNames.spokeA
    location: spokeALocation
    tags: tags
  }
}

module rgB '../modules/resource-group.bicep' = {
  name: 'kvsync-rg-b-${suffix}'
  scope: subscription(spokeBSubscriptionId)
  params: {
    name: rgNames.spokeB
    location: spokeBLocation
    tags: tags
  }
}

// ------------------------------------------------------------------ custom roles (hub subscription)
module roles '../modules/roles.bicep' = {
  name: 'kvsync-roles-${suffix}'
  params: {
    suffix: suffix
    importerSubscriptionIds: [
      spokeASubscriptionId
      spokeBSubscriptionId
    ]
  }
}

// ------------------------------------------------------------------ destination (consumer) vaults
// In real life these already exist and belong to the application teams.
module vaultA '../modules/vault.bicep' = {
  name: 'kvsync-vault-a-${suffix}'
  scope: resourceGroup(spokeASubscriptionId, rgNames.spokeA)
  params: {
    name: 'kv-dst-a-${suffix}'
    location: spokeALocation
    tags: tags
    purgeProtection: spokeAPurgeProtection
  }
  dependsOn: [
    rgA
  ]
}

module vaultB '../modules/vault.bicep' = {
  name: 'kvsync-vault-b-${suffix}'
  scope: resourceGroup(spokeBSubscriptionId, rgNames.spokeB)
  params: {
    name: 'kv-dst-b-${suffix}'
    location: spokeBLocation
    tags: tags
    purgeProtection: spokeBPurgeProtection
  }
  dependsOn: [
    rgB
  ]
}

// ------------------------------------------------------------------ the factory
module hub '../modules/hub.bicep' = {
  name: 'kvsync-hub-${suffix}'
  scope: resourceGroup(rgNames.hub)
  params: {
    suffix: suffix
    location: hubLocation
    tags: tags
    networkMode: 'public'
    destinations: [
      {
        key: 'a'
        uri: vaultA.outputs.vaultUri
      }
      {
        key: 'b'
        uri: vaultB.outputs.vaultUri
      }
    ]
    sourcePurgeProtection: false // proof of concept only
    operatorObjectId: operatorObjectId
    operatorPrincipalType: operatorPrincipalType
    enableRenewApp: true
    caProvider: 'testca'
    renewSettings: renewSettings
    reconcileSchedule: reconcileSchedule
    renewSchedule: renewSchedule
    packageBaseUri: packageBaseUri
    alertEmailAddresses: alertEmailAddresses
    issuerRoleDefinitionId: roles.outputs.issuerRoleDefinitionId
  }
  dependsOn: [
    rgHub
  ]
}

// ------------------------------------------------------------------ access to the destination vaults
module accessA '../modules/destination-access.bicep' = {
  name: 'kvsync-access-a-${suffix}'
  scope: resourceGroup(spokeASubscriptionId, rgNames.spokeA)
  params: {
    vaultName: vaultA.outputs.name
    syncPrincipalId: hub.outputs.syncPrincipalId
    syncIdentityId: hub.outputs.syncIdentityId
    importerRoleDefinitionId: roles.outputs.importerRoleDefinitionId
    workspaceId: hub.outputs.workspaceId
    operatorObjectId: operatorObjectId
    operatorPrincipalType: operatorPrincipalType
  }
}

module accessB '../modules/destination-access.bicep' = {
  name: 'kvsync-access-b-${suffix}'
  scope: resourceGroup(spokeBSubscriptionId, rgNames.spokeB)
  params: {
    vaultName: vaultB.outputs.name
    syncPrincipalId: hub.outputs.syncPrincipalId
    syncIdentityId: hub.outputs.syncIdentityId
    importerRoleDefinitionId: roles.outputs.importerRoleDefinitionId
    workspaceId: hub.outputs.workspaceId
    operatorObjectId: operatorObjectId
    operatorPrincipalType: operatorPrincipalType
  }
}

// ------------------------------------------------------------------ outputs
// Same names and shapes as the outputs of terraform/poc, so tests/live/*.py run unchanged against this deployment:
//   az deployment sub show --name <deployment name> --query properties.outputs > outputs.json
output tenant_id string = tenant().tenantId

output resource_groups object = {
  hub: rgNames.hub
  spoke_a: rgNames.spokeA
  spoke_b: rgNames.spokeB
}

output source_vault object = {
  id: hub.outputs.sourceVault.id
  name: hub.outputs.sourceVault.name
  uri: hub.outputs.sourceVault.uri
  subscription: subscription().subscriptionId
}

output destination_vaults object = {
  a: {
    id: vaultA.outputs.id
    name: vaultA.outputs.name
    uri: vaultA.outputs.vaultUri
    subscription: spokeASubscriptionId
  }
  b: {
    id: vaultB.outputs.id
    name: vaultB.outputs.name
    uri: vaultB.outputs.vaultUri
    subscription: spokeBSubscriptionId
  }
}

output function_apps object = hub.outputs.functionApps
output identities object = hub.outputs.identities
output queues object = hub.outputs.queues
output log_analytics_customer_id string = hub.outputs.logAnalyticsCustomerId

output role_definitions object = {
  importer: roles.outputs.importerRoleDefinitionId
  issuer: roles.outputs.issuerRoleDefinitionId
}

output event_grid_system_topic string = hub.outputs.eventGridSystemTopic
