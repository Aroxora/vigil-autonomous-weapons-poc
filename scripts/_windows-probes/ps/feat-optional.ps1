Get-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue |
  Where-Object { $_.State -ne 'Disabled' } |
  Select-Object FeatureName,State,CustomProperties
