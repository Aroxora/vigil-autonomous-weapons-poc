if(-not (Get-Command choco -ErrorAction SilentlyContinue)){ @() ; return }
& choco list -lo --limit-output --no-color 2>$null | ForEach-Object {
  $parts = $_ -split '\|'
  if($parts.Count -ge 2){ [pscustomobject]@{ source='choco'; name=$parts[0]; version=$parts[1] } }
}
