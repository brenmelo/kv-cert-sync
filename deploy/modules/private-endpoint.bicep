// A private endpoint for one Azure resource, optionally registered in a private DNS zone.
// Used in private mode only. The VNet, the subnet and the private DNS zones belong to the landing zone and are passed in.
targetScope = 'resourceGroup'

param name string
param location string = resourceGroup().location
param tags object = {}

@description('Subnet that receives the private endpoint.')
param subnetId string

@description('Resource that the private endpoint connects to.')
param targetResourceId string

@description('Sub-resource: vault, blob, queue, table or sites.')
param groupId string

@description('Private DNS zone for the endpoint. Leave empty when a central policy registers the DNS records.')
param dnsZoneId string = ''

resource endpoint 'Microsoft.Network/privateEndpoints@2024-05-01' = {
  name: name
  location: location
  tags: tags
  properties: {
    subnet: {
      id: subnetId
    }
    privateLinkServiceConnections: [
      {
        name: 'psc-${groupId}'
        properties: {
          privateLinkServiceId: targetResourceId
          groupIds: [
            groupId
          ]
        }
      }
    ]
  }
}

resource zoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-05-01' = if (!empty(dnsZoneId)) {
  parent: endpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: groupId
        properties: {
          privateDnsZoneId: dnsZoneId
        }
      }
    ]
  }
}

output id string = endpoint.id
