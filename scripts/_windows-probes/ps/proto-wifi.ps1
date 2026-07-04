$out = & netsh wlan show interfaces 2>$null
if(-not $out){ [pscustomobject]@{ skipped='no wlan or netsh wlan unavailable' } ; return }
$blob = $out | Out-String
$lines = $blob -split "`r?`n"
[pscustomobject]@{
  raw    = $blob.Substring(0, [Math]::Min(1200, $blob.Length))
  ssid   = ($lines | Where-Object { $_ -match '^\s+SSID\s*:' } | Select-Object -First 1)
  auth   = ($lines | Where-Object { $_ -match '^\s+Authentication\s*:' } | Select-Object -First 1)
  cipher = ($lines | Where-Object { $_ -match '^\s+Cipher\s*:' } | Select-Object -First 1)
}
