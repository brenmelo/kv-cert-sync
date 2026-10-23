// Intentionally empty: a nested deployment that creates nothing.
//
// Azure Resource Manager has no "sleep". A chain of these (a serial loop in function-app.bicep) is the only wait that needs no
// extra service, storage key, identity or script. Each one takes about 3 seconds to run.
targetScope = 'resourceGroup'
