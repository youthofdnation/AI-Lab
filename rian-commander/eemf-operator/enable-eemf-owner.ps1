[CmdletBinding()]
param([switch]$Enable,[switch]$Disable,[switch]$Restart)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if($env:COMPUTERNAME -ine 'DESKTOP-EEMFO3L'){throw 'Only DESKTOP-EEMFO3L may enable its operating permissions.'}
if($Enable -and $Disable){throw 'Choose one operation.'}
$agentDir=Join-Path $env:LOCALAPPDATA 'RIANCommander'
$config=Join-Path $agentDir 'config.json'
$agent=Join-Path $agentDir 'agent.ps1'
if(!(Test-Path -LiteralPath $config -PathType Leaf) -or !(Test-Path -LiteralPath $agent -PathType Leaf)){throw 'Existing RIAN Commander agent is not installed.'}
$settings=Get-Content -LiteralPath $config -Raw -Encoding UTF8 | ConvertFrom-Json
if($settings.device -ne 'DESKTOP-EEMFO3L' -or $settings.server -ne 'https://rian-commander-relay-production.up.railway.app'){throw 'Wrong device or server.'}
if($settings.root -ne $env:USERPROFILE){throw 'Agent root differs from expected user profile.'}
if($settings.token -isnot [string] -or $settings.token.Length -lt 40){throw 'Existing device token not configured.'}

if(-not $Enable -and -not $Disable){
 [pscustomobject]@{device=$settings.device;can_exec=[bool]$settings.can_exec;can_write=[bool]$settings.can_write;mode='StatusOnly';existing_agent=$true;changes='None'} | ConvertTo-Json -Compress
 exit 0
}

$target=if($Enable){$true}else{$false}
$settings.can_exec=$target
$settings.can_write=$target
# Save ACL-identical replacement to avoid weakening the device-token protection.
$oldAcl=Get-Acl -LiteralPath $config
$tmp=Join-Path $agentDir ('config-'+[guid]::NewGuid().ToString('N')+'.tmp')
try{
 $json=$settings | ConvertTo-Json -Depth 5
 [System.IO.File]::WriteAllText($tmp,$json,(New-Object System.Text.UTF8Encoding($false)))
 Set-Acl -LiteralPath $tmp -AclObject $oldAcl
 Move-Item -LiteralPath $tmp -Destination $config -Force
 Set-Acl -LiteralPath $config -AclObject $oldAcl
} finally {
 if(Test-Path -LiteralPath $tmp){Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue}
}
# Restart the known agent only. No other processes or files are changed.
$processes=@(Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -and $_.CommandLine.Contains($agent) -and $_.CommandLine.Contains($config) })
foreach($item in $processes){Stop-Process -Id $item.ProcessId -ErrorAction Stop}
$exe=Join-Path $PSHOME 'powershell.exe'
$arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "'+$agent+'" -ConfigPath "'+$config+'"'
Start-Process -FilePath $exe -ArgumentList $arguments -WindowStyle Hidden
[pscustomobject]@{device='DESKTOP-EEMFO3L';can_exec=$target;can_write=$target;restarted=$true;mode=if($Enable){'OwnerOptIn'}else{'OwnerReverted'}} | ConvertTo-Json -Compress
