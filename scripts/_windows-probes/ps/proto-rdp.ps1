$ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
$winstation = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue
[pscustomobject]@{
  fDenyTSConnections = $ts.fDenyTSConnections
  UserAuthentication = $winstation.UserAuthentication
  MinEncryptionLevel = $winstation.MinEncryptionLevel
  SecurityLayer      = $winstation.SecurityLayer
  PortNumber         = $winstation.PortNumber
}
