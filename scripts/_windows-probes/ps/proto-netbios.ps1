Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue | Where-Object IPEnabled | ForEach-Object {
  [pscustomobject]@{
    description         = $_.Description
    tcpipNetbiosOptions = $_.TcpipNetbiosOptions
    macAddress          = if($_.MACAddress){ 'present' } else { '' }
  }
}
