$svc = Get-Service WinHttpAutoProxySvc -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType
$reg = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSDrive,PSProvider
[pscustomobject]@{ service=$svc; wpadKey=$reg }
