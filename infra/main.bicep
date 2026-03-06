@description('The Azure region to deploy resources into.')
param location string = resourceGroup().location

@description('Name of the App Service Plan.')
param appServicePlanName string = 'baremetalweb-plan'

@description('Name of the dev/staging Web App.')
param webAppName string = 'baremetalweb'

@description('Name of the production Web App.')
param webAppProdName string = 'baremetalweb-prod'

@description('Name of the CI reset Web App (L1.1 fresh-deploy tests).')
param webAppCiResetName string = 'baremetalweb-cireset'

@description('Name of the upgrade-path CI Web App (L1.1-upgrade / L1.2).')
param webAppUpgradeName string = 'baremetalweb-upgrade'

@description('Name of the canary ring-0 Web App (L2.1 staging).')
param webAppCanaryName string = 'baremetalweb-canary'

// App Service Plan: P0V3 (Premium v3)
resource appServicePlan 'Microsoft.Web/serverfarms@2023-01-01' = {
  name: appServicePlanName
  location: location
  sku: {
    name: 'P0v3'
    tier: 'PremiumV3'
    capacity: 1
  }
  kind: 'app'
  properties: {
    reserved: false
  }
}

// Dev / staging Web App
resource webApp 'Microsoft.Web/sites@2023-01-01' = {
  name: webAppName
  location: location
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    siteConfig: {
      alwaysOn: true
      netFrameworkVersion: 'v9.0'
      use32BitWorkerProcess: false
    }
  }
}

// Production Web App
resource webAppProd 'Microsoft.Web/sites@2023-01-01' = {
  name: webAppProdName
  location: location
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    siteConfig: {
      alwaysOn: true
      netFrameworkVersion: 'v9.0'
      use32BitWorkerProcess: false
    }
  }
}

// CI Reset Web App — blown away and redeployed with empty data on each CI run
resource webAppCiReset 'Microsoft.Web/sites@2023-01-01' = {
  name: webAppCiResetName
  location: location
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    siteConfig: {
      alwaysOn: false
      netFrameworkVersion: 'v9.0'
      use32BitWorkerProcess: false
    }
  }
}

// Upgrade CI Web App — runs with a standard data set from a previous version
resource webAppUpgrade 'Microsoft.Web/sites@2023-01-01' = {
  name: webAppUpgradeName
  location: location
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    siteConfig: {
      alwaysOn: false
      netFrameworkVersion: 'v9.0'
      use32BitWorkerProcess: false
    }
  }
}

// Canary Ring-0 Web App — release candidate deployed here for soak testing
resource webAppCanary 'Microsoft.Web/sites@2023-01-01' = {
  name: webAppCanaryName
  location: location
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    siteConfig: {
      alwaysOn: true
      netFrameworkVersion: 'v9.0'
      use32BitWorkerProcess: false
    }
  }
}
