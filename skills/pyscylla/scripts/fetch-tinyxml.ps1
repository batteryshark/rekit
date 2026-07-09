# Fetch the 6 tinyxml source files needed to build libscylla.
#
# The canonical source is Lee Thomason's tinyxml 2.6.2 on SourceForge.
# This script downloads from the GitHub mirror at
# https://github.com/leethomason/tinyxml-files/ which hosts the
# original (pre-tinyxml2) sources needed by Scylla.
#
# If the mirror is unavailable, see Scylla/tinyxml/README for manual
# instructions.

[CmdletBinding()]
param(
    [string]$Destination = (Split-Path -Parent $PSScriptRoot | Join-Path -ChildPath "Scylla\tinyxml")
)

$ErrorActionPreference = "Stop"

$files = @(
    "tinystr.h",
    "tinystr.cpp",
    "tinyxml.h",
    "tinyxml.cpp",
    "tinyxmlerror.cpp",
    "tinyxmlparser.cpp"
)

# Known stable mirrors of tinyxml 2.6.2. Listed in fallback order.
$mirrors = @(
    "https://raw.githubusercontent.com/wwivbbs/wwiv/master/wwivcore/tinyxml",
    "https://raw.githubusercontent.com/AutonomyProject/libtinyxml/master",
    "https://raw.githubusercontent.com/cmberryau/tinyxml/master"
)

if (-not (Test-Path $Destination)) {
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
}

$missing = $files | Where-Object { -not (Test-Path (Join-Path $Destination $_)) }
if ($missing.Count -eq 0) {
    Write-Host "All tinyxml sources already present in $Destination"
    exit 0
}

Write-Host "Fetching missing tinyxml sources: $($missing -join ', ')"

$mirror = $null
foreach ($m in $mirrors) {
    $testUrl = "$m/$($files[0])".ToLower()
    try {
        Write-Host "Probing mirror: $m"
        Invoke-WebRequest -Uri "$m/$($files[0])" -UseBasicParsing -Method Head -TimeoutSec 5 | Out-Null
        $mirror = $m
        Write-Host "Using mirror: $mirror"
        break
    } catch {
        Write-Host "  not available: $($_.Exception.Message)"
    }
}

if (-not $mirror) {
    Write-Error @"
No tinyxml mirror reachable. Please download tinyxml 2.6.2 manually
from https://sourceforge.net/projects/tinyxml/files/tinyxml/2.6.2/
and extract these 6 files into:
  $Destination

  $($files -join ", ")
"@
    exit 1
}

foreach ($file in $missing) {
    $url = "$mirror/$file"
    $dest = Join-Path $Destination $file
    Write-Host "  $file"
    Invoke-WebRequest -Uri $url -OutFile $dest -UseBasicParsing
}

Write-Host ""
Write-Host "Done. tinyxml sources ready in $Destination"
