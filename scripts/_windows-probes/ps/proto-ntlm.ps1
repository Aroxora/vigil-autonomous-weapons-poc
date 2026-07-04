$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
$ntlm = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction SilentlyContinue
[pscustomobject]@{
  LmCompatibilityLevel         = $lsa.LmCompatibilityLevel
  NoLMHash                     = $lsa.NoLMHash
  RestrictAnonymous            = $lsa.RestrictAnonymous
  RestrictAnonymousSAM         = $lsa.RestrictAnonymousSAM
  NtlmMinClientSec             = $ntlm.NtlmMinClientSec
  NtlmMinServerSec             = $ntlm.NtlmMinServerSec
  RestrictReceivingNTLMTraffic = $ntlm.RestrictReceivingNTLMTraffic
  RestrictSendingNTLMTraffic   = $ntlm.RestrictSendingNTLMTraffic
}
