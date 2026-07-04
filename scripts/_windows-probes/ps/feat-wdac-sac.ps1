$sac = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -ErrorAction SilentlyContinue).VerifiedAndReputablePolicyState
$applocker = try { (Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue | Out-String) } catch { '' }
$ciInfo = Get-CimInstance -Namespace root\Microsoft\Windows\CI -ClassName CIPolicyInfo -ErrorAction SilentlyContinue | Select-Object FriendlyName,PolicyOptions,PolicyType,Version
[pscustomobject]@{
  smartAppControl_state = $sac
  appLockerPolicyExcerpt = if($applocker){ $applocker.Substring(0, [Math]::Min(600, $applocker.Length)) } else { '' }
  ciPolicyInfo = $ciInfo
}
