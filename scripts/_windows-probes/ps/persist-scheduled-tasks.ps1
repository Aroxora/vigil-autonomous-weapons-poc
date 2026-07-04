Get-ScheduledTask -ErrorAction SilentlyContinue |
  Where-Object { $_.State -ne 'Disabled' } |
  ForEach-Object {
    $exec = ($_.Actions | Where-Object { $_.Execute } | Select-Object -ExpandProperty Execute) -join ';'
    $args = ($_.Actions | Where-Object { $_.Arguments } | Select-Object -ExpandProperty Arguments) -join ';'
    [pscustomobject]@{
      taskPath = $_.TaskPath
      taskName = $_.TaskName
      state    = "$($_.State)"
      author   = $_.Author
      execute  = if($exec){ $exec.Substring(0, [Math]::Min(160, $exec.Length)) } else { '' }
      arguments = if($args){ $args.Substring(0, [Math]::Min(160, $args.Length)) } else { '' }
      lastRunTime = $_.LastRunTime
      nextRunTime = $_.NextRunTime
    }
  } | Sort-Object taskPath,taskName
