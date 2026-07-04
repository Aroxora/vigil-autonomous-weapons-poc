$au = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty PSPath,PSParentPath,PSChildName,PSDrive,PSProvider
$svc = Get-Service wuauserv -ErrorAction SilentlyContinue | Select-Object Name,Status,StartType
$hotfixes = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 25 HotFixID,Description,InstalledOn
[pscustomobject]@{ uxSettings=$au; service=$svc; recentHotfixes=$hotfixes }
