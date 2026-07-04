$out = @()
$browserDirs = @(
  @{ browser='chrome'; root=Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data' },
  @{ browser='edge';   root=Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data' },
  @{ browser='brave';  root=Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data' }
)
foreach($b in $browserDirs){
  if(-not (Test-Path $b.root)){ continue }
  $profiles = Get-ChildItem -Path $b.root -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' }
  foreach($prof in $profiles){
    $extDir = Join-Path $prof.FullName 'Extensions'
    if(-not (Test-Path $extDir)){ continue }
    Get-ChildItem -Path $extDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
      $extId = $_.Name
      $versionDir = Get-ChildItem -Path $_.FullName -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
      if($versionDir){
        $manifestPath = Join-Path $versionDir.FullName 'manifest.json'
        $name = ''; $version = ''
        if(Test-Path $manifestPath){
          try {
            $j = Get-Content $manifestPath -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
            $name = "$($j.name)"
            $version = "$($j.version)"
          } catch { }
        }
        $out += [pscustomobject]@{
          browser = $b.browser
          profile = $prof.Name
          extensionId = $extId
          name = $name
          version = $version
        }
      }
    }
  }
}
# Firefox: scan profiles for extensions.json
$ffRoot = Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles'
if(Test-Path $ffRoot){
  Get-ChildItem -Path $ffRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $extJson = Join-Path $_.FullName 'extensions.json'
    if(Test-Path $extJson){
      try {
        $j = Get-Content $extJson -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
        foreach($a in $j.addons){
          $out += [pscustomobject]@{
            browser = 'firefox'
            profile = $_.Name
            extensionId = $a.id
            name = $a.defaultLocale.name
            version = $a.version
          }
        }
      } catch { }
    }
  }
}
$out
