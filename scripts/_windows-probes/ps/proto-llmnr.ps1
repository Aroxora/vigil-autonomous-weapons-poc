$dns = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue
$mdns = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -ErrorAction SilentlyContinue
[pscustomobject]@{
  LLMNR_EnableMulticast = $dns.EnableMulticast
  mDNS_EnableMDNS       = $mdns.EnableMDNS
}
