Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
  Where-Object { $_.StartMode -ne 'Disabled' } |
  Select-Object Name,DisplayName,StartMode,State,StartName,PathName |
  Sort-Object Name
