# scripts/build.ps1 builds all tunel binaries. Requires MinGW-w64 in PATH for
# the GUI build (which needs CGO for Fyne) and the VPN build (which needs CGO
# for the wireguard/tun package via wintun).
#
# Uso:
#   .\scripts\build.ps1                  # construye los 4 binarios + VPN con GUI
#   .\scripts\build.ps1 -NoCGO           # omite la GUI y la VPN, sólo CLI (sin MinGW)
#   .\scripts\build.ps1 -NoGUI           # omite sólo la GUI, mantiene VPN
#   .\scripts\build.ps1 -NoVPN           # omite sólo la VPN, mantiene GUI

[CmdletBinding()]
param(
  [switch]$NoCGO,
  [switch]$NoGUI,
  [switch]$NoVPN,
  [int]$Jobs = 0
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
if ($env:CGO_ENABLED -eq "") { $env:CGO_ENABLED = "1" }
$env:GOFLAGS = "-mod=mod"
if ($Jobs -gt 0) { $env:GOMAXPROCS = $Jobs }

# tunels soporta --vpn sin CGO (el servidor sólo enruta paquetes, no abre TUN).
Write-Host "==> tunels.exe      (servidor)" -ForegroundColor Cyan
go build -o tunels.exe ./cmd/tunels
if ($LASTEXITCODE -ne 0) { throw "build tunels failed" }

Write-Host "==> tunel-cert.exe  (generador de certs)" -ForegroundColor Cyan
go build -o tunel-cert.exe ./cmd/tunel-cert
if ($LASTEXITCODE -ne 0) { throw "build tunel-cert failed" }

Write-Host "==> tunel-echo.exe  (servidor de eco)" -ForegroundColor Cyan
go build -o tunel-echo.exe ./cmd/tunel-echo
if ($LASTEXITCODE -ne 0) { throw "build tunel-echo failed" }

if ($NoCGO) {
  Write-Host "==> tunelc.exe      (cliente, modo CLI, sin CGO)" -ForegroundColor Cyan
  go build -o tunelc.exe ./cmd/tunelc
  if ($LASTEXITCODE -ne 0) { throw "build tunelc (no CGO) failed" }
} else {
  $tags = @()
  if (-not $NoGUI) { $tags += "gui" }
  if (-not $NoVPN) { $tags += "vpn" }
  $tagArg = if ($tags.Count -gt 0) { "-tags", ($tags -join ",") } else { @() }
  $ldflags = if (-not $NoGUI) { "-H windowsgui" } else { "" }
  Write-Host ("==> tunelc.exe      (cliente, tags: {0})" -f ($tags -join ",")) -ForegroundColor Cyan
  if ($tags.Count -gt 0 -and $ldflags -ne "") {
    go build -tags ($tags -join ",") -ldflags $ldflags -o tunelc.exe ./cmd/tunelc
  } elseif ($tags.Count -gt 0) {
    go build -tags ($tags -join ",") -o tunelc.exe ./cmd/tunelc
  } elseif ($ldflags -ne "") {
    go build -ldflags $ldflags -o tunelc.exe ./cmd/tunelc
  } else {
    go build -o tunelc.exe ./cmd/tunelc
  }
  if ($LASTEXITCODE -ne 0) { throw "build tunelc (GUI/VPN) failed" }
}

Write-Host ""
Write-Host "Build completo:" -ForegroundColor Green
Get-ChildItem *.exe | Select-Object Name, @{n='MB';e={[math]::Round($_.Length/1MB,1)}}, LastWriteTime