[CmdletBinding()]
param([switch]$Enable,[switch]$Disable)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:COMPUTERNAME -ne 'DESKTOP-1QGT8D6') {throw 'This poller only supports DESKTOP-1QGT8D6.'}
if ($Enable -and $Disable) {throw 'Choose only one action.'}
$root=Split-Path -Parent $MyInvocation.MyCommand.Path
$script=Join-Path $root 'run-once.ps1'
$credentials=Join-Path $root 'runner-credentials.dpapi.json'
$taskName='RIAN-Commander-D23-Restricted-Audit'
$existing=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if (-not $Enable -and -not $Disable) {
    [pscustomobject]@{
        Device='DESKTOP-1QGT8D6'
        TaskName=$taskName
        Registered=[bool]$existing
        Enabled=if($existing){[bool]($existing.State -ne 'Disabled')}else{$false}
        Interval='2 minutes'
        Mode='ReadOnlyCheck'
        Changes='None'
    } | ConvertTo-Json -Compress
    exit 0
}
if($Disable){
    if($existing){Unregister-ScheduledTask -TaskName $taskName -Confirm:$false}
    Write-Output 'D23 automatic observation poller disabled. Existing Commander unchanged.'
    exit 0
}
if(-not(Test-Path -LiteralPath $script -PathType Leaf)){throw 'Missing approved runner script'}
if(-not(Test-Path -LiteralPath $credentials -PathType Leaf)){throw 'D23 runner enrollment required'}
if($existing){throw 'Scheduled task exists. Disable explicitly before re-enabling.'}
# The task runs only in the already logged-in Windows user session.
# No admin SYSTEM principal, no automatic privilege elevation or arbitrary command.
$identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name
$action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoLogo -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "'+$script+'" -Run')
$trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 2)
$principal=New-ScheduledTaskPrincipal -UserId $identity -LogonType Interactive -RunLevel Limited
$settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'One allowlisted D23 audit observation; cannot run training. Only fetches separately owner-approved jobs.' | Out-Null
Write-Output 'D23 poller enabled for current signed-in user; every 2 minutes. Training NOT started.'
