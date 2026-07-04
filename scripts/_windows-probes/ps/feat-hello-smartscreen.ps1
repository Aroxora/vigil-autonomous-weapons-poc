$hello = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork' -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSDrive,PSProvider
$smartScreen = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -ErrorAction SilentlyContinue).SmartScreenEnabled
$edgeSmartScreen = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -ErrorAction SilentlyContinue).SmartScreenEnabled
[pscustomobject]@{
  helloPolicy        = $hello
  explorerSmartScreen = $smartScreen
  edgeSmartScreen     = $edgeSmartScreen
}
