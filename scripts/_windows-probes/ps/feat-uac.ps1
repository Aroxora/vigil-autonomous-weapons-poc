$p = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
[pscustomobject]@{
  EnableLUA                  = $p.EnableLUA
  ConsentPromptBehaviorAdmin = $p.ConsentPromptBehaviorAdmin
  ConsentPromptBehaviorUser  = $p.ConsentPromptBehaviorUser
  PromptOnSecureDesktop      = $p.PromptOnSecureDesktop
  EnableSecureUIAPaths       = $p.EnableSecureUIAPaths
  FilterAdministratorToken   = $p.FilterAdministratorToken
  EnableInstallerDetection   = $p.EnableInstallerDetection
}
