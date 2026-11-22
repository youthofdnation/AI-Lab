<#
RIAN Commander V2 agent: one-time per-user setup (no administrator rights).

  .\install-v2-agent.ps1                         # status only, changes nothing
  .\install-v2-agent.ps1 -Install -ConfigPath C:\path\agent.json
  .\install-v2-agent.ps1 -Uninstall              # removes the logon task only

-Install copies the three reviewed agent files to
%LOCALAPPDATA%\RIAN-Commander-V2\agent, copies the owner-prepared config, limits
the folder ACL to the current user, and registers a per-user logon Scheduled Task
that runs the agent hidden with pythonw. After that the owner never needs to open
PowerShell or type a password for jobs that a standing grant already covers.

Nothing here opens a listening port, edits firewall/Tailscale rules, changes
another user's settings, installs Python, or touches the legacy agent config.
Mail data, credentials and the device token stay on this PC. -Uninstall never
deletes mail data or the index.
#>
param([switch]$Install,[switch]$Uninstall,[string]$ConfigPath)
$ErrorActionPreference='Stop'
$taskName='RIAN Commander V2 Agent'
$base=Join-Path $env:LOCALAPPDATA 'RIAN-Commander-V2'
$agentDir=Join-Path $base 'agent'
$files=@('rian-v2-agent.py','rian_mail_index.py','tenant-artifact-agent.py','rian_fleet_tasks.py','youngmin_qlora_measure.py')
$who="$env:USERDOMAIN\$env:USERNAME"

function Get-RianStatus {
  $task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
  $python=Get-Command pythonw.exe -ErrorAction SilentlyContinue
  [pscustomobject]@{
    computer=$env:COMPUTERNAME; user=$who; installed_files=(Test-Path -LiteralPath (Join-Path $agentDir 'rian-v2-agent.py'))
    config=(Test-Path -LiteralPath (Join-Path $base 'agent.json')); task=if($task){$task.State.ToString()}else{'NOT_REGISTERED'}
    pythonw=if($python){$python.Source}else{'NOT_FOUND'}
  } | ConvertTo-Json
}

if(-not $Install -and -not $Uninstall){ Get-RianStatus; return }
if($Install -and $Uninstall){ throw 'Choose -Install or -Uninstall, not both' }

if($Uninstall){
  if(Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue){
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
  }
  Write-Output 'RIAN V2 agent logon task removed. Agent files, journal and mail index were left in place.'
  Get-RianStatus; return
}

if(-not $ConfigPath -or -not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)){ throw 'Pass -ConfigPath to an owner-prepared agent.json' }
$cfg=Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
foreach($key in 'relay_url','device_id','state_dir','allowed_kinds'){ if(-not $cfg.$key){ throw "agent.json is missing $key" } }
if($cfg.relay_url -notmatch '^https://'){ throw 'relay_url must be https://' }
if($cfg.device_id -ine $env:COMPUTERNAME){ throw "agent.json device_id does not match this PC ($env:COMPUTERNAME)" }
if($cfg.allow_test_loopback){ throw 'allow_test_loopback is for automated tests only' }
$pythonw=(Get-Command pythonw.exe -ErrorAction SilentlyContinue).Source
if(-not $pythonw){ throw 'pythonw.exe not found in PATH. Install Python 3.10+ for this user first (not done automatically).' }

New-Item -ItemType Directory -Force -Path $agentDir | Out-Null
foreach($f in $files){ Copy-Item -LiteralPath (Join-Path $PSScriptRoot $f) -Destination (Join-Path $agentDir $f) -Force }
$targetConfig=Join-Path $base 'agent.json'
Copy-Item -LiteralPath $ConfigPath -Destination $targetConfig -Force
# Current user only: no inherited access for other local accounts.
& icacls.exe $base /inheritance:r /grant:r "${who}:(OI)(CI)F" | Out-Null
if($LASTEXITCODE -ne 0){ throw 'Could not restrict folder permissions' }

$argsLine='"'+(Join-Path $agentDir 'rian-v2-agent.py')+'" run --config "'+$targetConfig+'"'
$action=New-ScheduledTaskAction -Execute $pythonw -Argument $argsLine -WorkingDirectory $agentDir
$trigger=New-ScheduledTaskTrigger -AtLogOn -User $who
$settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
$principal=New-ScheduledTaskPrincipal -UserId $who -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
Write-Output 'RIAN V2 agent registered for this user and started. It reconnects automatically after logon or reboot.'
Get-RianStatus
