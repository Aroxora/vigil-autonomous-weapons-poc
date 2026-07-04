$doh = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue | Select-Object ServerAddress,AllowFallbackToUdp,AutoUpgrade,DohTemplate
$servers = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object InterfaceAlias,ServerAddresses
[pscustomobject]@{ dohServers=$doh; resolvers=$servers }
