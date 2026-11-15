[CmdletBinding()]
param([switch]$Install)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if ($env:COMPUTERNAME -ne 'DESKTOP-1QGT8D6') { throw 'Only DESKTOP-1QGT8D6 is permitted.' }
$commit='dfaa84dfbd13e5ba75091f7992c19675da4ddfb2'
$base='https://raw.githubusercontent.com/youthofdnation/AI-Lab/' + $commit + '/rian-commander/d23-runner/'
$sha=@{
  'runner.py'='e579ccee1711c7dc872818a867822cff00a17f4d'
  'runner_client.py'='ac044cb2d785a1af648e6cc8cd5f3e8b9365ab35'
  'install-local.ps1'='19bd1d8b76b76261f2e4c4f142b43afee44b6f52'
  'enroll-local.ps1'='28bf12c2fa627536974f27bd120707d8e7d520dc'
  'run-once.ps1'='8c9fcaf36daccd3d16720b4ad8af5a1620ee5d1a'
  'test_runner.py'='1481baa3713985cb4220145b8576936613d71305'
  'test_runner_client.py'='2aa220573da6144f0e8caa66d7d342f99ec0457a'
}
$dir=Join-Path $env:TEMP ('rian-d23-install-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $dir -ErrorAction Stop | Out-Null
function BlobSha1([string]$path) {
  [byte[]]$body=[IO.File]::ReadAllBytes($path)
  [byte[]]$prefix=[Text.Encoding]::ASCII.GetBytes('blob '+$body.Length+[char]0)
  $all=New-Object byte[] ($prefix.Length+$body.Length)
  [Array]::Copy($prefix,0,$all,0,$prefix.Length)
  [Array]::Copy($body,0,$all,$prefix.Length,$body.Length)
  $hash=[Security.Cryptography.SHA1]::Create()
  try {return ([BitConverter]::ToString($hash.ComputeHash($all))).Replace('-','').ToLowerInvariant()}
  finally {$hash.Dispose();[Array]::Clear($all,0,$all.Length);[Array]::Clear($body,0,$body.Length)}
}
try {
  foreach ($name in $sha.Keys) {
    $file=Join-Path $dir $name
    Invoke-WebRequest -Uri ($base+$name) -OutFile $file -UseBasicParsing -TimeoutSec 30
    if ((BlobSha1 $file) -ne $sha[$name]) { throw "Downloaded file content mismatch: $name" }
  }
  if (-not $Install) {
    & (Join-Path $dir 'install-local.ps1')
    if (-not $?) {throw 'Preflight failed'}
    Write-Output 'Files verified; no installation performed. Re-run with -Install after local approval.'
  } else {
    & (Join-Path $dir 'install-local.ps1') -Install
    if (-not $?) {throw 'Installer failed'}
    Write-Output 'Installed locally only. No enrollment, background service or training was started.'
  }
} finally {
  if (Test-Path -LiteralPath $dir) {Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue}
}
