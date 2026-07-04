Get-WindowsCapability -Online -ErrorAction SilentlyContinue |
  Where-Object { $_.State -eq 'Installed' } |
  Select-Object Name,State
