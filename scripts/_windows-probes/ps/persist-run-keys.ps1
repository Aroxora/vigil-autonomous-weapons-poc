$paths = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)
$out = foreach($p in $paths){
  if(Test-Path $p){
    $k = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
    $k.PSObject.Properties | Where-Object { $_.Name -notin 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider' } | ForEach-Object {
      [pscustomobject]@{ hive=$p; name=$_.Name; command=("$($_.Value)").Substring(0, [Math]::Min(200, "$($_.Value)".Length)) }
    }
  }
}
$out
