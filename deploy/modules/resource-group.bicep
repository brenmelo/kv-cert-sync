// A resource group, created from a template that runs at subscription scope. Needed because a Bicep file can only create a
// resource group in the subscription it is deployed to; this module is deployed with `scope: subscription(<id>)` to create one in
// another subscription of the same tenant.
targetScope = 'subscription'

param name string
param location string
param tags object = {}

resource group 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: name
  location: location
  tags: tags
}

output name string = group.name
output id string = group.id
