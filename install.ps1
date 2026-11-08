param([switch]$UseExistingImages, [switch]$RegisterCli)

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Register-SurfaceMapCli {
    $bin = Join-Path $env:LOCALAPPDATA 'SurfaceMap\bin'
    New-Item -ItemType Directory -Path $bin -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'surfacemap.ps1') -Destination (Join-Path $bin 'entry.ps1') -Force
    Set-Content -LiteralPath (Join-Path $bin 'project-root.txt') -Value $PSScriptRoot -Encoding UTF8
    $launcher = @(
        '@echo off'
        '"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0entry.ps1" %*'
        'exit /b %errorlevel%'
    )
    Set-Content -LiteralPath (Join-Path $bin 'surfacemap.cmd') -Value $launcher -Encoding ASCII

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (($userPath -split ';').TrimEnd('\') -notcontains $bin.TrimEnd('\')) {
        $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
        try {
            $rawPath = $key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $expanded = $rawPath -and $key.GetValueKind('Path') -eq [Microsoft.Win32.RegistryValueKind]::ExpandString
            $updatedPath = if ($userPath) { $userPath.TrimEnd(';') + ';' + $bin } else { $bin }
            [Environment]::SetEnvironmentVariable('Path', $updatedPath, 'User')
            if ($expanded) {
                # Keep expandable entries after .NET broadcasts the new PATH.
                $key.SetValue('Path', $rawPath.TrimEnd(';') + ';' + $bin, [Microsoft.Win32.RegistryValueKind]::ExpandString)
            }
        } finally {
            $key.Dispose()
        }
    }
    if (($env:Path -split ';').TrimEnd('\') -notcontains $bin.TrimEnd('\')) {
        Write-Host 'Open a new terminal to use the surfacemap command.'
    }
    Write-Host 'SurfaceMap CLI: surfacemap help'
}

if ($RegisterCli) {
    Register-SurfaceMapCli
    exit 0
}

function Test-DockerEngine {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { return $false }
    cmd.exe /d /c 'docker info >nul 2>&1'
    return $LASTEXITCODE -eq 0
}

$dockerBin = Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin'
$env:Path = "$env:Path;$dockerBin"
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw 'Windows Package Manager is required to install Docker Desktop. Install App Installer and rerun.'
    }
    winget install --exact --id Docker.DockerDesktop --source winget
    if ($LASTEXITCODE -ne 0) { throw 'Docker Desktop installation did not complete. Review the installer output.' }
}
if (-not (Test-DockerEngine)) {
    $desktop = Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'
    if (Test-Path -LiteralPath $desktop) { Invoke-Item -LiteralPath $desktop }
    Write-Host 'Complete Docker Desktop setup if prompted. A first-time WSL installation may require a restart.'
}
for ($attempt = 0; $attempt -lt 60 -and -not (Test-DockerEngine); $attempt++) {
    Start-Sleep -Seconds 2
}
if (-not (Test-DockerEngine)) { throw 'Docker Engine is unavailable. Finish Docker Desktop setup and rerun.' }
$composeHelp = docker compose up --help
if ($LASTEXITCODE -ne 0 -or -not ($composeHelp -match '--wait-timeout')) {
    throw 'Update Docker Desktop to a version with Compose up --wait-timeout, then rerun.'
}
docker compose version
if (-not (Test-Path -LiteralPath '.env')) { Copy-Item -LiteralPath '.env.example' -Destination '.env' }
$buildOptions = @('--build')
if ($UseExistingImages) { $buildOptions = @('--no-build', '--pull', 'never') }
docker compose --env-file .env up -d @buildOptions --wait --wait-timeout 180
if ($LASTEXITCODE -ne 0) {
    if ($UseExistingImages) {
        throw 'Could not start from local images. Confirm a previous installation exists, the port is free, and the containers are healthy.'
    }
    throw 'SurfaceMap could not start. Review the error above. On registry or download errors, check Docker DNS and proxy settings and retry. For an existing installation, try -UseExistingImages.'
}
$binding = docker compose --env-file .env port web 80
if ($LASTEXITCODE -ne 0 -or $binding -notmatch ':(\d+)$') { throw 'Could not determine the dashboard port.' }
$url = "http://127.0.0.1:$($Matches[1])"
Write-Host "Dashboard: $url"
Register-SurfaceMapCli
Write-Host 'Full stop: surfacemap stop (or double-click stop.cmd)'

$seconds = 1800
if ($env:SURFACEMAP_INSTALL_TIMEOUT_SECONDS -and (
    -not [int]::TryParse($env:SURFACEMAP_INSTALL_TIMEOUT_SECONDS, [ref]$seconds) -or $seconds -lt 0
)) { throw 'SURFACEMAP_INSTALL_TIMEOUT_SECONDS must be a non-negative integer.' }
$deadline = (Get-Date).AddSeconds($seconds)
$previous = -1
do {
    $tools = @()
    try { $tools = Invoke-RestMethod "$url/api/tools" -TimeoutSec 8 } catch {}
    $installed = @($tools | Where-Object { $_.active_adapter -and $_.status -eq 'installed' }).Count
    if ($installed -ne $previous) { Write-Host "Ready tools: $installed/8"; $previous = $installed }
    if ($installed -eq 8) { Write-Host "SurfaceMap and all tools are ready at $url"; exit 0 }
    if ((Get-Date) -lt $deadline) { Start-Sleep -Seconds 5 }
} while ((Get-Date) -lt $deadline)
throw "Tool setup is still incomplete. Open $url and review Tool Manager, then rerun the installer."
