$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue | Select-Object Caption,Version,BuildNumber,OperatingSystemSKU,InstallDate,LastBootUpTime,FreePhysicalMemory,TotalVisibleMemorySize
$pl = Get-ComputerInfo -ErrorAction SilentlyContinue | Select-Object CsDomain,CsDomainRole,WindowsProductName,WindowsEditionId,WindowsInstallationType,OsHardwareAbstractionLayer,BiosBIOSVersion,CsManufacturer,CsModel
[pscustomobject]@{ os=$os; profile=$pl }
