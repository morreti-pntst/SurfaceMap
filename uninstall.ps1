$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

Write-Host 'This permanently deletes SurfaceMap projects, scan results, installed scanners and local configuration.'
if ((Read-Host 'Type DELETE to continue') -cne 'DELETE') {
    Write-Host 'Uninstall cancelled.'
    exit 0
}

$env:Path += ';' + (Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin')
docker compose -f compose.yaml down --remove-orphans --volumes --rmi local
if ($LASTEXITCODE -ne 0) { throw 'Docker cleanup failed. Start Docker Desktop and retry.' }

$bin = Join-Path $env:LOCALAPPDATA 'SurfaceMap\bin'
$pointer = Join-Path $bin 'project-root.txt'
if ((Test-Path -LiteralPath $pointer) -and
    (Get-Content -LiteralPath $pointer -Encoding UTF8 -TotalCount 1) -eq $PSScriptRoot) {
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
    if ($key) {
        try {
            $rawPath = $key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            if ($rawPath) {
                $kind = $key.GetValueKind('Path')
                $entries = @($rawPath -split ';' | Where-Object {
                    [Environment]::ExpandEnvironmentVariables($_).TrimEnd('\') -ne $bin
                })
                $updated = $entries -join ';'
                if ($updated -ne $rawPath) {
                    [Environment]::SetEnvironmentVariable('Path', [Environment]::ExpandEnvironmentVariables($updated), 'User')
                    if ($updated -and $kind -eq [Microsoft.Win32.RegistryValueKind]::ExpandString) {
                        $key.SetValue('Path', $updated, $kind)
                    }
                }
            }
        } finally {
            $key.Dispose()
        }
    }
    foreach ($name in @('surfacemap.cmd', 'entry.ps1', 'project-root.txt')) {
        $file = Join-Path $bin $name
        if (Test-Path -LiteralPath $file -PathType Leaf) { Remove-Item -LiteralPath $file }
    }
    if (-not (Get-ChildItem -LiteralPath $bin -Force)) { Remove-Item -LiteralPath $bin }
}
if (Test-Path -LiteralPath '.env' -PathType Leaf) { Remove-Item -LiteralPath '.env' }
if ((Test-Path -LiteralPath '.data' -PathType Container) -and -not (Get-ChildItem -LiteralPath '.data' -Force)) {
    Remove-Item -LiteralPath '.data'
}
Write-Host 'SurfaceMap was uninstalled. You can now delete this folder and close the terminal.'
