$pref = Get-MpPreference -ErrorAction SilentlyContinue
if(-not $pref){ [pscustomobject]@{ skipped='Get-MpPreference unavailable' } ; return }
$ids = @($pref.AttackSurfaceReductionRules_Ids)
$acts = @($pref.AttackSurfaceReductionRules_Actions)
$rules = for($i=0; $i -lt $ids.Count; $i++){
  [pscustomobject]@{ id=$ids[$i]; action=if($i -lt $acts.Count){$acts[$i]}else{$null} }
}
[pscustomobject]@{
  asrRules                     = $rules
  enableControlledFolderAccess = $pref.EnableControlledFolderAccess
  controlledFolderAccessProtectedFolders = $pref.ControlledFolderAccessProtectedFolders
  controlledFolderAccessAllowedApplications = $pref.ControlledFolderAccessAllowedApplications
  enableNetworkProtection      = $pref.EnableNetworkProtection
  puaProtection                = $pref.PUAProtection
  cloudBlockLevel              = $pref.CloudBlockLevel
  mapsReporting                = $pref.MAPSReporting
  submitSamplesConsent         = $pref.SubmitSamplesConsent
  disableScriptScanning        = $pref.DisableScriptScanning
  disableArchiveScanning       = $pref.DisableArchiveScanning
  disableRealtimeMonitoring    = $pref.DisableRealtimeMonitoring
  signatureFallbackOrder       = $pref.SignatureFallbackOrder
}
