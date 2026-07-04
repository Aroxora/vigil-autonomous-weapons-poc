Get-Package -ErrorAction SilentlyContinue -ProviderName 'Programs','msi','msu' 2>$null | ForEach-Object {
  [pscustomobject]@{
    source       = 'getpackage'
    name         = $_.Name
    version      = "$($_.Version)"
    providerName = "$($_.ProviderName)"
    summary      = if($_.Summary){ "$($_.Summary)".Substring(0, [Math]::Min(160, "$($_.Summary)".Length)) } else { '' }
  }
} | Sort-Object name -Unique
