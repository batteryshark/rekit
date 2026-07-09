# Build pe_unmapper.exe from source (libpeconv-backed)
#
# Prerequisites:
#   - Visual Studio 2022 with the v143 toolset (Desktop C++ workload)
#   - CMake 3.20+
#
# This rebuilds the vendored bin/pe_unmapper.exe from the upstream sources.
# The committed binary is a Release x64 build; re-run this to refresh + re-pin.
#
# Usage (PowerShell on a Windows build host):
#   .\scripts\build.ps1
#
# Sources are NOT vendored in this skill (too large). Clone upstream:
#   git clone --recursive https://github.com/hasherezade/pe_unmapper.git
#   cd pe_unmapper
# then run CMake:
param(
    [string]$SourceDir = "../../pe_unmapper-src",
    [string]$Config = "Release"
)

if (!(Test-Path $SourceDir)) {
    git clone --recursive https://github.com/hasherezade/pe_unmapper.git $SourceDir
}

Push-Location $SourceDir
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config $Config --target pe_unmapper
Pop-Location

$built = Join-Path $SourceDir "build/pe_unmapper/$Config/pe_unmapper.exe"
$dest = Join-PSScriptRoot "../bin/pe_unmapper.exe"
Copy-Item $built $dest -Force
Write-Host "pe_unmapper.exe built and copied to $dest"
