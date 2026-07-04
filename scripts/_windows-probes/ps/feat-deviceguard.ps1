$dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
if(-not $dg){ [pscustomobject]@{ skipped='Win32_DeviceGuard unavailable' } ; return }
[pscustomobject]@{
  AvailableSecurityProperties           = $dg.AvailableSecurityProperties
  CodeIntegrityPolicyEnforcementStatus  = $dg.CodeIntegrityPolicyEnforcementStatus
  UsermodeCodeIntegrityPolicyEnforcementStatus = $dg.UsermodeCodeIntegrityPolicyEnforcementStatus
  SecurityServicesConfigured            = $dg.SecurityServicesConfigured
  SecurityServicesRunning               = $dg.SecurityServicesRunning
  VirtualizationBasedSecurityStatus     = $dg.VirtualizationBasedSecurityStatus
  RequiredSecurityProperties            = $dg.RequiredSecurityProperties
  Version                               = $dg.Version
}
