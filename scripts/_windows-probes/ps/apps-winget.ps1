if(-not (Get-Command winget -ErrorAction SilentlyContinue)){ @() ; return }
$raw = (& winget list --accept-source-agreements 2>$null) | Out-String
$lines = $raw -split "`r?`n"
$headerIx = ($lines | Select-String -Pattern '^Name\s+Id\s+Version' | Select-Object -First 1).LineNumber
if(-not $headerIx){ @() ; return }
$header = $lines[$headerIx-1]
$idCol  = $header.IndexOf('Id')
$verCol = $header.IndexOf('Version')
$availCol = $header.IndexOf('Available')
$srcCol = $header.IndexOf('Source')
for($i=$headerIx+1; $i -lt $lines.Count; $i++){
  $l = $lines[$i]
  if($l -match '^[-]+\s*$' -or $l.Trim().Length -eq 0){ continue }
  if($l.Length -lt ($idCol+1)){ continue }
  $name = $l.Substring(0, $idCol).TrimEnd()
  $id   = if($verCol -gt 0){ $l.Substring($idCol, $verCol-$idCol).Trim() } else { '' }
  $ver  = if($availCol -gt 0 -and $l.Length -ge $availCol){ $l.Substring($verCol, $availCol-$verCol).Trim() } elseif($l.Length -gt $verCol){ $l.Substring($verCol).Trim() } else { '' }
  $avail = if($srcCol -gt 0 -and $l.Length -ge $srcCol){ $l.Substring($availCol, $srcCol-$availCol).Trim() } else { '' }
  $src  = if($srcCol -gt 0 -and $l.Length -gt $srcCol){ $l.Substring($srcCol).Trim() } else { '' }
  [pscustomobject]@{ source='winget'; name=$name; id=$id; version=$ver; available=$avail; pkgSource=$src }
}
