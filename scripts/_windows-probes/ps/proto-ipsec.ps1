$rules = Get-NetIPsecRule -PolicyStore ActiveStore -ErrorAction SilentlyContinue
[pscustomobject]@{
  activeRuleCount  = ($rules | Measure-Object).Count
  enabledRuleCount = (($rules | Where-Object Enabled -EQ True) | Measure-Object).Count
}
