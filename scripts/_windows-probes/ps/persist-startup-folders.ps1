$folders = @(
  [Environment]::GetFolderPath('Startup'),
  [Environment]::GetFolderPath('CommonStartup')
)
$out = foreach($f in $folders){
  if($f -and (Test-Path $f)){
    Get-ChildItem -Path $f -Force -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime,@{n='folder';e={$f}}
  }
}
$out
