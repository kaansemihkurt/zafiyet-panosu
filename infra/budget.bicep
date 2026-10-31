// Bütçe alarmı (kaynak grubu kapsamı). Ayrı dosya: bazı abonelik türlerinde Consumption API
// kısıtlı olabileceği için ana dağıtımı engellemesin diye.
// az deployment group create -g rg-zafiyet-panosu -f infra/budget.bicep -p alertEmail=<e-posta> startDate=2026-11-01
param alertEmail string
@description('Ayın ilk günü, YYYY-MM-DD')
param startDate string
@description('Aylık bütçe (fatura para birimi, Azure for Students için USD).')
param amount int = 1

resource budget 'Microsoft.Consumption/budgets@2023-05-01' = {
  name: 'zafiyetpano-budget'
  properties: {
    category: 'Cost'
    amount: amount
    timeGrain: 'Monthly'
    timePeriod: { startDate: startDate }
    notifications: {
      actual50: { enabled: true, operator: 'GreaterThan', threshold: 50, thresholdType: 'Actual', contactEmails: [ alertEmail ] }
      actual100: { enabled: true, operator: 'GreaterThan', threshold: 100, thresholdType: 'Actual', contactEmails: [ alertEmail ] }
      forecast100: { enabled: true, operator: 'GreaterThan', threshold: 100, thresholdType: 'Forecasted', contactEmails: [ alertEmail ] }
    }
  }
}
