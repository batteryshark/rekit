# Build libscylla with VS 2022 / v143.
#
# Prerequisites:
#   - VS 2022 Community + Desktop C++ workload (v143 toolset)
#   - diStorm sources at Scylla/diStorm/        (already vendored)
#   - tinyxml sources at Scylla/tinyxml/        (must be obtained)
#
# See Scylla/tinyxml/README for tinyxml files.
# WTL is NOT required for libscylla (only for the original GUI build).

[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [ValidateSet("Win32", "x64", "Both")]
    [string]$Platform = "Both",

    [string]$MSBuild = (
        "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
    ),

    [switch]$SkipDependencyFetch
)

$ErrorActionPreference = "Stop"
$repoRoot   = Split-Path -Parent $PSScriptRoot
$scyllaSln  = Join-Path $repoRoot "Scylla\Scylla.sln"

if (-not (Test-Path $MSBuild)) {
    Write-Error "MSBuild not found at: $MSBuild"
    exit 1
}

# Ensure tinyxml sources are present
$tinyxmlDir = Join-Path $repoRoot "Scylla\tinyxml"
$needed = @("tinystr.h","tinystr.cpp","tinyxml.h","tinyxml.cpp","tinyxmlerror.cpp","tinyxmlparser.cpp")
$missing = $needed | Where-Object { -not (Test-Path (Join-Path $tinyxmlDir $_)) }
if ($missing -and -not $SkipDependencyFetch) {
    Write-Host "tinyxml sources missing; fetching..." -ForegroundColor Yellow
    & (Join-Path $PSScriptRoot "fetch-tinyxml.ps1")
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Could not fetch tinyxml. Resolve manually and re-run with -SkipDependencyFetch."
        exit $LASTEXITCODE
    }
} elseif ($missing) {
    Write-Error "tinyxml sources missing and -SkipDependencyFetch set. Files needed: $($missing -join ', ')"
    exit 1
}

$platforms = if ($Platform -eq "Both") { @("Win32", "x64") } else { @($Platform) }

foreach ($plat in $platforms) {
    Write-Host ""
    Write-Host "==> Building libscylla $Configuration|$plat" -ForegroundColor Cyan
    & $MSBuild $scyllaSln `
        /t:libscylla `
        /p:Configuration=$Configuration `
        /p:Platform=$plat `
        /m /v:minimal
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Build failed for $Configuration|$plat (exit $LASTEXITCODE)"
        exit $LASTEXITCODE
    }
}

Write-Host ""
Write-Host "Done. Release DLLs copied to pyscylla/bin/ by post-build event." -ForegroundColor Green
