$p = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' -ErrorAction SilentlyContinue
[pscustomobject]@{
  SupportedEncryptionTypes       = $p.SupportedEncryptionTypes
  ClientIPAddresses              = $p.ClientIPAddresses
  MaxPacketSize                  = $p.MaxPacketSize
  DefaultDomainSupportedEncTypes = $p.DefaultDomainSupportedEncTypes
}
