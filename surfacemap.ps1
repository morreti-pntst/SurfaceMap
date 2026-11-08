param([string]$Action = 'help')

$ErrorActionPreference = 'Stop'
$usage = 'Usage: surfacemap {start|stop|restart|status|logs|update|doctor|tools|version|help} [service]'
if ($Action -in @('help', '-h', '--help')) { Write-Output $usage; exit 0 }
if ($Action -eq 'version') { Write-Output 'SURFACEMAP 0.6.0'; exit 0 }
if ($Action -notin @('start', 'stop', 'restart', 'status', 'logs', 'update', 'doctor', 'tools')) {
    [Console]::Error.WriteLine($usage)
    exit 2
}

$root = $PSScriptRoot
if (-not (Test-Path -LiteralPath (Join-Path $root 'compose.yaml'))) {
    $root = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'project-root.txt') -Encoding UTF8 -TotalCount 1
}
if (-not (Test-Path -LiteralPath (Join-Path $root 'compose.yaml'))) {
    throw 'SurfaceMap has moved. Run install.ps1 -RegisterCli from the new project folder.'
}
Set-Location -LiteralPath $root
$dockerBin = Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin'
$env:Path = "$env:Path;$dockerBin"

function Start-SurfaceMap {
    param([switch]$Rebuild)
    $installer = Join-Path $root 'install.ps1'
    if ($Rebuild) {
        & $installer
    } else {
        & $installer -UseExistingImages
    }
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

function Get-DashboardUrl {
    # A stopped web service has no published port. Docker reports that on stderr.
    $ErrorActionPreference = 'Continue'
    $binding = docker compose -f compose.yaml port web 80 2>$null
    if ($LASTEXITCODE -eq 0 -and $binding -match ':(\d+)$') {
        "http://127.0.0.1:$($Matches[1])"
    }
}

switch ($Action) {
    'start' { Start-SurfaceMap }
    'stop' {
        & (Join-Path $root 'stop.cmd') --no-pause
        exit $LASTEXITCODE
    }
    'restart' {
        & (Join-Path $root 'stop.cmd') --no-pause
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        Start-SurfaceMap
    }
    'status' {
        docker compose -f compose.yaml ps
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        $url = Get-DashboardUrl
        if ($url) {
            Invoke-RestMethod "$url/api/system/status" -TimeoutSec 8 | ConvertTo-Json -Compress
        } else {
            Write-Output 'SurfaceMap is stopped. Run surfacemap start to launch it.'
        }
    }
    'logs' {
        docker compose -f compose.yaml logs -f @args
        exit $LASTEXITCODE
    }
    'update' {
        docker compose -f compose.yaml pull db redis
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        Start-SurfaceMap -Rebuild
    }
    'doctor' {
        docker compose version
        if ($LASTEXITCODE -ne 0) { throw 'Docker with Compose v2 is required.' }
        docker info --format 'Docker Engine {{.ServerVersion}}'
        if ($LASTEXITCODE -ne 0) { throw 'Start Docker Desktop and retry.' }
        docker compose -f compose.yaml config --quiet
        if ($LASTEXITCODE -ne 0) { throw 'Review .env and compose.yaml.' }
        Write-Output 'Compose configuration is valid.'
        docker compose -f compose.yaml ps
        exit $LASTEXITCODE
    }
    'tools' {
        $url = Get-DashboardUrl
        if (-not $url) { throw 'SurfaceMap is stopped. Run surfacemap start first.' }
        (Invoke-WebRequest "$url/api/tools" -UseBasicParsing -TimeoutSec 8).Content
    }
}
exit 0
