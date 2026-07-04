Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue |
  Select-Object Name,Command,Location,User
