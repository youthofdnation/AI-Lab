[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$Upgrade
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$expected = 'DESKTOP-1QGT8D6'
if ($env:COMPUTERNAME -ne $expected) {
    throw 'Refusing installation: this package targets DESKTOP-1QGT8D6 only.'
}
$source = Split-Path -Parent $MyInvocation.MyCommand.Path
$files = @('runner.py','runner_client.py')
foreach ($name in $files) {
    if (-not (Test-Path -LiteralPath (Join-Path $source $name) -PathType Leaf)) {
        throw "Missing runner component: $name"
    }
}
$py = Get-Command 'python' -ErrorAction SilentlyContinue
if (-not $py) { throw 'Python is required before installing.' }
$tests = & python -m unittest discover -s $source -p 'test_*.py' -v 2>&1
if ($LASTEXITCODE -ne 0) { throw 'Unit tests failed: installation aborted.' }
$dest = Join-Path $env:LOCALAPPDATA 'RIANCommander\D23RestrictedRunner'
if (-not $Install) {
    [pscustomobject]@{
        Device = $expected
        Mode = 'VerifyOnly'
        Tests = 'PASS'
        InstallRequested = $false
        Destination = $dest
        Changes = 'None'
    } | ConvertTo-Json -Compress
    exit 0
}
if ((Test-Path -LiteralPath $dest) -and -not $Upgrade) {
    throw 'Target exists: explicit -Upgrade required, no files changed.'
}
$parent = Split-Path -Parent $dest
New-Item -ItemType Directory -Path $parent -Force | Out-Null
$staging = Join-Path $parent ('D23Runner-stage-' + [guid]::NewGuid().ToString('N'))
try {
    New-Item -ItemType Directory -Path $staging -ErrorAction Stop | Out-Null
    $inventory = @()
    foreach ($name in $files) {
        $from = Join-Path $source $name
        $to = Join-Path $staging $name
        Copy-Item -LiteralPath $from -Destination $to -ErrorAction Stop
        $a = (Get-FileHash -LiteralPath $from -Algorithm SHA256).Hash
        $b = (Get-FileHash -LiteralPath $to -Algorithm SHA256).Hash
        if ($a -ne $b) { throw "Hash verification failed: $name" }
        $inventory += [pscustomobject]@{ File = $name; SHA256 = $a }
    }
    $receipt = [pscustomobject]@{
        Product = 'RIAN Commander Restricted D23 Runner'
        Device = $expected
        InstalledUtc = [DateTime]::UtcNow.ToString('o')
        AutorunEnabled = $false
        ExistingCommanderModified = $false
        SecretsStored = $false
        Files = $inventory
    }
    $receipt | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $staging 'install-receipt.json') -Encoding UTF8
    if (Test-Path -LiteralPath $dest) {
        throw 'Upgrade replacement needs a reviewed procedure; original remains intact.'
    }
    Move-Item -LiteralPath $staging -Destination $dest -ErrorAction Stop
    Write-Output "Installed without service registration: $dest"
} finally {
    if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
}
