[CmdletBinding()]
param([switch]$Run)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if ($env:COMPUTERNAME -ne 'DESKTOP-1QGT8D6') {throw 'Only DESKTOP-1QGT8D6 may run this task.'}
$root=Split-Path -Parent $MyInvocation.MyCommand.Path
$secretsPath=Join-Path $root 'runner-credentials.dpapi.json'
if (-not (Test-Path -LiteralPath $secretsPath -PathType Leaf)) {throw 'Runner must be enrolled first.'}
if (-not (Test-Path -LiteralPath (Join-Path $root 'runner_client.py') -PathType Leaf)) {throw 'Runner is missing.'}
if (-not $Run) {
    [pscustomobject]@{Device='DESKTOP-1QGT8D6'; Mode='VerifyOnly'; Registered=$true; Changes='None'} | ConvertTo-Json -Compress
    exit 0
}
$store=Get-Content -LiteralPath $secretsPath -Raw | ConvertFrom-Json
if ($store.device -ne 'DESKTOP-1QGT8D6' -or $store.broker -ne 'https://rian-d23-restricted-broker-production.up.railway.app') {throw 'Credential origin mismatch.'}
function Unprotect([string]$cipher){
    $ss=ConvertTo-SecureString -String $cipher
    $ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
    try {return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)}
    finally {[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)}
}
if ($env:RIAN_D23_RUNNER_TOKEN -or $env:RIAN_D23_TASK_KEY) {throw 'Refusing to overwrite existing environment secrets.'}
try {
    $env:RIAN_D23_RUNNER_TOKEN=Unprotect $store.runner_token_dpapi
    $env:RIAN_D23_TASK_KEY=Unprotect $store.task_key_dpapi
    $env:RIAN_D23_BROKER_URL=$store.broker
    & python (Join-Path $root 'runner_client.py') --once
    if ($LASTEXITCODE -ne 0) {throw "Runner returned non-zero status."}
} finally {
    Remove-Item Env:\RIAN_D23_RUNNER_TOKEN -ErrorAction SilentlyContinue
    Remove-Item Env:\RIAN_D23_TASK_KEY -ErrorAction SilentlyContinue
    Remove-Item Env:\RIAN_D23_BROKER_URL -ErrorAction SilentlyContinue
}
