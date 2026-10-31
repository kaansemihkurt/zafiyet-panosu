// Zafiyet İstihbarat Panosu — Azure altyapısı (kaynak grubu kapsamı)
// Dağıtım:  az deployment group create -g rg-zafiyet-panosu -f infra/main.bicep -p alertEmail=<e-posta>
// Tüm kaynaklar ücretsiz katman / Azure for Students kredisi içinde; hedef maliyet 0 TL.

@description('Kaynak adlarının ön eki (küçük harf, rakam).')
param prefix string = 'zafiyetpano'

@description('Static Web Apps bölgesi (westeurope, centralus, eastus2, westus2, eastasia).')
param location string = 'westeurope'

@description('Alarm e-postalarının gideceği adres.')
param alertEmail string

@description('Tablo SAS süresinin bitişi (dönem sonu).')
param sasExpiry string = '2027-02-28T00:00:00Z'

var suffix = uniqueString(resourceGroup().id)
var storageName = take('${prefix}${suffix}', 24)

// ---------- Gözlemlenebilirlik: log toplama ----------
resource law 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: '${prefix}-law'
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
    workspaceCapping: { dailyQuotaGb: json('0.1') } // maliyet tavanı: günde en fazla 100 MB
  }
}

resource appi 'Microsoft.Insights/components@2020-02-02' = {
  name: '${prefix}-appi'
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: law.id
    DisableIpMasking: false // IP adresleri maskelenir (KVKK)
  }
}

// ---------- Veri: izleme listesi tablosu ----------
resource st 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageName
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    allowSharedKeyAccess: true // SAS üretimi için gerekli; anahtar kimseye verilmez
    publicNetworkAccess: 'Enabled'
  }
}

resource tableService 'Microsoft.Storage/storageAccounts/tableServices@2023-01-01' = {
  parent: st
  name: 'default'
}

resource watchlistTable 'Microsoft.Storage/storageAccounts/tableServices/tables@2023-01-01' = {
  parent: tableService
  name: 'watchlist'
}

// ---------- Uygulama: Static Web Apps (Free) ----------
resource swa 'Microsoft.Web/staticSites@2023-01-01' = {
  name: '${prefix}-swa'
  location: location
  sku: { name: 'Free', tier: 'Free' }
  properties: {
    stagingEnvironmentPolicy: 'Disabled' // PR önizleme ortamı yok: korunan veri yalnızca üretimde
    allowConfigFileUpdates: true
  }
}

// En az yetki: SAS yalnızca Table servisi (t), yalnızca nesne düzeyi (o), yalnızca r/a/u/d,
// yalnızca HTTPS ve süreli. Hesap anahtarı hiçbir yere yazılmaz; SAS doğrudan uygulama ayarına gider.
var tableSas = st.listAccountSas('2023-01-01', {
  signedServices: 't'
  signedResourceTypes: 'o'
  signedPermission: 'raud'
  signedProtocol: 'https'
  signedExpiry: sasExpiry
}).accountSasToken

resource swaSettings 'Microsoft.Web/staticSites/config@2023-01-01' = {
  parent: swa
  name: 'appsettings'
  properties: {
    TABLE_ENDPOINT: 'https://${st.name}.table.${environment().suffixes.storage}'
    TABLE_NAME: watchlistTable.name
    TABLE_SAS: tableSas
    APPLICATIONINSIGHTS_CONNECTION_STRING: appi.properties.ConnectionString
    AUDIT_SALT: uniqueString(resourceGroup().id, 'audit-salt')
  }
}

// ---------- Alarm: tekrarlanan reddedilen / başarısız istekler ----------
resource ag 'Microsoft.Insights/actionGroups@2023-01-01' = {
  name: '${prefix}-ag'
  location: 'global'
  properties: {
    groupShortName: 'zafiyetpano'
    enabled: true
    emailReceivers: [ { name: 'sahip', emailAddress: alertEmail, useCommonAlertSchema: true } ]
  }
}

resource deniedAlert 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: '${prefix}-denied-requests'
  location: 'global'
  properties: {
    description: '5 dakikada 5\'ten fazla başarısız istek (403 dahil): olası yetkisiz erişim denemesi veya hata artışı.'
    severity: 2
    enabled: true
    scopes: [ appi.id ]
    evaluationFrequency: 'PT1M'
    windowSize: 'PT5M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'failedRequests'
          criterionType: 'StaticThresholdCriterion'
          metricNamespace: 'microsoft.insights/components'
          metricName: 'requests/failed'
          operator: 'GreaterThan'
          threshold: 5
          timeAggregation: 'Count'
        }
      ]
    }
    actions: [ { actionGroupId: ag.id } ]
  }
}

output staticWebAppName string = swa.name
output url string = 'https://${swa.properties.defaultHostname}'
output storageAccount string = st.name
output appInsights string = appi.name
