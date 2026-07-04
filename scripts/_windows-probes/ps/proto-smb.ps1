$srv = Get-SmbServerConfiguration -ErrorAction SilentlyContinue | Select-Object EnableSMB1Protocol,EnableSMB2Protocol,RequireSecuritySignature,EncryptData,EnableSecuritySignature,RejectUnencryptedAccess,EnableLeasing
$cli = Get-SmbClientConfiguration -ErrorAction SilentlyContinue | Select-Object EnableSecuritySignature,RequireSecuritySignature,EnableMultiChannel,EnableInsecureGuestLogons
$feat = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue | Select-Object State
[pscustomobject]@{ server=$srv; client=$cli; smb1Feature=$feat }
