$base = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
$out = @{}
foreach($v in 'SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1','TLS 1.2','TLS 1.3'){
  $row = @{}
  foreach($side in 'Client','Server'){
    $k = Join-Path $base "$v\$side"
    if(Test-Path $k){
      $p = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
      $row[$side] = @{ Enabled=$p.Enabled; DisabledByDefault=$p.DisabledByDefault }
    } else { $row[$side] = $null }
  }
  $out[$v] = $row
}
[pscustomobject]@{ schannel=$out }
