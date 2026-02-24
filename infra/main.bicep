@description('The Azure region to deploy resources into.')
param location string = resourceGroup().location

@description('Name of the App Service Plan.')
param appServicePlanName string = 'baremetalweb-plan'

@description('Name of the dev/staging Web App.')
param webAppName string = 'baremetalweb'

@description('Name of the production Web App.')
param webAppProdName string = 'baremetalweb-prod'

@description('Custom domain name for the dev web app. Leave empty to skip custom domain binding.')
param customDomainName string = 'metal.willeastbury.com'

// App Service Plan: P0V3 (Premium v3) - updated from F1 (Free)
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

// App Service managed certificate - automatically provisioned and renewed for the custom domain
resource managedCert 'Microsoft.Web/certificates@2023-01-01' = if (!empty(customDomainName)) {
  name: '${customDomainName}-${webAppName}'
  location: location
  properties: {
    serverFarmId: appServicePlan.id
    canonicalName: customDomainName
  }
}

// Custom hostname binding - preserves the custom domain and SNI SSL binding across redeployments
resource hostNameBinding 'Microsoft.Web/sites/hostNameBindings@2023-01-01' = if (!empty(customDomainName)) {
  parent: webApp
  name: customDomainName
  properties: {
    siteName: webAppName
    hostNameType: 'Verified'
    customHostNameDnsRecordType: 'CName'
    sslState: 'SniEnabled'
    thumbprint: managedCert.properties.thumbprint
  }
}
