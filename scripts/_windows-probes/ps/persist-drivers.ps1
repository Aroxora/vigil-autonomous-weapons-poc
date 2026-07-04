Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue |
  Where-Object { $_.State -eq 'Running' -or $_.StartMode -eq 'Auto' } |
  ForEach-Object {
    $path = ($_.PathName -replace '^\\\\\?\\','') -replace '"',''
    $sig = $null
    if($path -and (Test-Path $path)){
      try {
        $s = Get-AuthenticodeSignature -FilePath $path -ErrorAction SilentlyContinue
        $sig = @{
          status = "$($s.Status)"
          signerCert_Subject = if($s.SignerCertificate){ $s.SignerCertificate.Subject } else { $null }
          signerCert_Issuer  = if($s.SignerCertificate){ $s.SignerCertificate.Issuer } else { $null }
        }
      } catch { }
    }
    [pscustomobject]@{
      name = $_.Name
      caption = $_.Caption
      pathName = $path
      state = $_.State
      startMode = $_.StartMode
      serviceType = $_.ServiceType
      signature = $sig
    }
  } | Sort-Object name
