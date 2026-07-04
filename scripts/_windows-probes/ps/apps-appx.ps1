Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | ForEach-Object {
  [pscustomobject]@{
    source          = 'appx'
    name            = $_.Name
    version         = $_.Version
    publisher       = $_.Publisher
    packageFullName = $_.PackageFullName
    installLocation = $_.InstallLocation
    signatureKind   = "$($_.SignatureKind)"
    isFramework     = [bool]$_.IsFramework
    nonRemovable    = [bool]$_.NonRemovable
  }
} | Sort-Object name -Unique
