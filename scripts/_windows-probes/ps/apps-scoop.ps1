if(-not (Get-Command scoop -ErrorAction SilentlyContinue)){ @() ; return }
$raw = (& scoop list 2>$null) | Out-String
$lines = $raw -split "`r?`n"
$headerIx = ($lines | Select-String -Pattern '^Name\s+Version\s+Source' | Select-Object -First 1).LineNumber
if(-not $headerIx){ @() ; return }
for($i=$headerIx+1; $i -lt $lines.Count; $i++){
  $l = $lines[$i]
  if($l -match '^[-]+\s' -or $l.Trim().Length -eq 0){ continue }
  $tok = $l -split '\s+'
  if($tok.Count -ge 3){ [pscustomobject]@{ source='scoop'; name=$tok[0]; version=$tok[1]; bucket=$tok[2] } }
}
