[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$EnrollmentCode,
    [string]$BrokerUrl = 'https://rian-d23-restricted-broker-production.up.railway.app'
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:COMPUTERNAME -ne 'DESKTOP-1QGT8D6') { throw 'This enrollment is restricted to DESKTOP-1QGT8D6.' }
if ($EnrollmentCode -notmatch '^[A-Za-z0-9_-]{32}$') { throw 'Invalid enrollment code.' }
$url = [Uri]::new($BrokerUrl)
if ($url.Scheme -ne 'https' -or $url.Host -ne 'rian-d23-restricted-broker-production.up.railway.app' -or $url.AbsolutePath -ne '/' -or $url.Query -or $url.Fragment -or $url.UserInfo) { throw 'Untrusted broker URL.' }
$installDir=Join-Path $env:LOCALAPPDATA 'RIANCommander\D23RestrictedRunner'
if (!(Test-Path -LiteralPath (Join-Path $installDir 'runner.py') -PathType Leaf)) { throw 'Install verified runner first.' }
if (!(Test-Path -LiteralPath (Join-Path $installDir 'runner_client.py') -PathType Leaf)) { throw 'Install verified runner first.' }
$credentialFile=Join-Path $installDir 'runner-credentials.dpapi.json'
if (Test-Path -LiteralPath $credentialFile) { throw 'Already enrolled: manual credential rotation required.' }
$payload=@{device='DESKTOP-1QGT8D6';code=$EnrollmentCode} | ConvertTo-Json -Compress
$res=Invoke-RestMethod -Method Post -Uri "$BrokerUrl/v1/d23/enrollment/claim" -ContentType 'application/json' -Body $payload -TimeoutSec 20
if ($res.device -ne 'DESKTOP-1QGT8D6' -or $res.registered -ne $true -or $res.runner_token.Length -lt 48 -or $res.task_key.Length -lt 32) { throw 'Enrollment response invalid.' }
# Windows DPAPI protects values for this Windows account only. Never echo them to the console.
$runnerSecret=ConvertTo-SecureString -String $res.runner_token -AsPlainText -Force | ConvertFrom-SecureString
$signingSecret=ConvertTo-SecureString -String $res.task_key -AsPlainText -Force | ConvertFrom-SecureString
$receipt=@{
  device='DESKTOP-1QGT8D6'
  broker=$BrokerUrl
  runner_token_dpapi=$runnerSecret
  task_key_dpapi=$signingSecret
  enrolled_utc=[DateTime]::UtcNow.ToString('o')
}
$js=$receipt | ConvertTo-Json -Compress -Depth 4
if($js.Length -gt 5000){throw 'Refusing oversized credentials.'}
$bytes=[System.Text.Encoding]::UTF8.GetBytes($js)
$stream=[System.IO.File]::Open($credentialFile,[System.IO.FileMode]::CreateNew,[System.IO.FileAccess]::Write,[System.IO.FileShare]::None)
try{$stream.Write($bytes,0,$bytes.Length)}finally{$stream.Dispose();[array]::Clear($bytes,0,$bytes.Length)}
$acl=Get-Acl -LiteralPath $credentialFile
$acl.SetAccessRuleProtection($true,$false)
$user=[System.Security.Principal.WindowsIdentity]::GetCurrent().User
$rule=New-Object System.Security.AccessControl.FileSystemAccessRule($user,'FullControl','Allow')
$acl.SetAccessRule($rule)
Set-Acl -LiteralPath $credentialFile -AclObject $acl
Write-Output 'D23 runner enrollment saved for current Windows user. No background service or training started.'
