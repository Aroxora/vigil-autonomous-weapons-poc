$tx   = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue
$sbl  = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue
$mll  = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction SilentlyContinue
$exec = Get-ExecutionPolicy -List | Select-Object Scope,ExecutionPolicy
[pscustomobject]@{
  versionTable                 = $PSVersionTable.PSVersion.ToString()
  executionPolicy              = $exec
  scriptBlockLogging           = $sbl.EnableScriptBlockLogging
  scriptBlockInvocationLogging = $sbl.EnableScriptBlockInvocationLogging
  moduleLogging                = $mll.EnableModuleLogging
  transcription                = $tx.EnableTranscripting
  transcriptionDir             = $tx.OutputDirectory
}
