$svc = Get-Service WinRM -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType
$listeners = ''
$serviceConfig = ''
if($svc -and $svc.Status -eq 'Running'){
  try { $listeners = (& winrm enumerate winrm/config/Listener 2>$null | Out-String) } catch { }
  try { $serviceConfig = (& winrm get winrm/config/Service 2>$null | Out-String) } catch { }
}
[pscustomobject]@{ service=$svc; listeners=$listeners; serviceConfig=$serviceConfig }
