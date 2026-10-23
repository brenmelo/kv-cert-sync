// A MINIMAL landing zone to try deploy/production in an empty subscription: one VNet, three subnets and the five private DNS
// zones that the factory's private endpoints use. Real environments already have these (usually a hub VNet with central DNS):
// pass THEIR ids to deploy/production and do not use this file.
//
// Resource group scope:
//   az group create --name rg-kvsync-net --location <region>
//   az deployment group create --resource-group rg-kvsync-net --template-file deploy/production/examples/landing-zone.bicep
//
// The outputs are the network inputs of deploy/production.
targetScope = 'resourceGroup'

param location string = resourceGroup().location
param tags object = {}

@description('Name of the VNet.')
param vnetName string = 'vnet-kvsync'

@description('Address space of the VNet (a /24 or larger). It must not overlap a network you peer it with.')
param addressPrefix string = '10.77.0.0/24'

@description('Give the two function subnets default outbound internet access. The factory sends its telemetry to Application Insights and may reach destination vaults over their public endpoints; with no egress path (NAT gateway, firewall, private endpoints for everything) it cannot. Switch it off when your landing zone already provides egress.')
param functionSubnetsDefaultOutbound bool = true

var zones = {
  vault: 'privatelink.vaultcore.azure.net'
  blob: 'privatelink.blob.${environment().suffixes.storage}'
  queue: 'privatelink.queue.${environment().suffixes.storage}'
  table: 'privatelink.table.${environment().suffixes.storage}'
  sites: 'privatelink.azurewebsites.net'
}

resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: vnetName
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [
        addressPrefix
      ]
    }
    subnets: [
      {
        name: 'snet-private-endpoints'
        properties: {
          addressPrefix: cidrSubnet(addressPrefix, 26, 0)
          defaultOutboundAccess: false
        }
      }
      {
        name: 'snet-func-sync'
        properties: {
          addressPrefix: cidrSubnet(addressPrefix, 26, 1)
          defaultOutboundAccess: functionSubnetsDefaultOutbound
          delegations: [
            {
              name: 'flex'
              properties: {
                serviceName: 'Microsoft.App/environments'
              }
            }
          ]
        }
      }
      {
        name: 'snet-func-renew'
        properties: {
          addressPrefix: cidrSubnet(addressPrefix, 26, 2)
          defaultOutboundAccess: functionSubnetsDefaultOutbound
          delegations: [
            {
              name: 'flex'
              properties: {
                serviceName: 'Microsoft.App/environments'
              }
            }
          ]
        }
      }
    ]
  }
}

resource zone 'Microsoft.Network/privateDnsZones@2024-06-01' = [for z in items(zones): {
  name: z.value
  location: 'global'
  tags: tags
}]

resource link 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2024-06-01' = [for (z, i) in items(zones): {
  parent: zone[i]
  name: 'link-${vnetName}'
  location: 'global'
  tags: tags
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: vnet.id
    }
  }
}]

output privateEndpointSubnetId string = '${vnet.id}/subnets/snet-private-endpoints'
output syncFunctionSubnetId string = '${vnet.id}/subnets/snet-func-sync'
output renewFunctionSubnetId string = '${vnet.id}/subnets/snet-func-renew'
// By name, not by position: items() returns the keys in alphabetical order.
output vaultPrivateDnsZoneId string = resourceId('Microsoft.Network/privateDnsZones', zones.vault)
output blobPrivateDnsZoneId string = resourceId('Microsoft.Network/privateDnsZones', zones.blob)
output queuePrivateDnsZoneId string = resourceId('Microsoft.Network/privateDnsZones', zones.queue)
output tablePrivateDnsZoneId string = resourceId('Microsoft.Network/privateDnsZones', zones.table)
output sitesPrivateDnsZoneId string = resourceId('Microsoft.Network/privateDnsZones', zones.sites)
