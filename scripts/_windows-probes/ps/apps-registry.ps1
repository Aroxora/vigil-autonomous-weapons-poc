$paths = @(
 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
$items = foreach($p in $paths){
  Get-ItemProperty -Path $p -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object {
    [pscustomobject]@{
      source          = 'registry'
      hive            = ($_.PSPath -split '::')[1] -replace '\\Software.+',''
      name            = $_.DisplayName
      version         = $_.DisplayVersion
      publisher       = $_.Publisher
      installDate     = $_.InstallDate
      installLocation = $_.InstallLocation
      estSizeKB       = $_.EstimatedSize
      systemComponent = [bool]$_.SystemComponent
    }
  }
}
$items | Where-Object { -not $_.systemComponent } | Sort-Object name -Unique
