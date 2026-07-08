# scripts/test-local.ps1
# Prueba end-to-end de Tunel en localhost. Arranca tunels + tunel-echo + tunelc,
# hace curl al puerto público y cierra todo.
#
# Uso:
#   .\scripts\test-local.ps1                  # prueba y limpia
#   .\scripts\test-local.ps1 -Keep            # deja todo corriendo
#   .\scripts\test-local.ps1 -Keep -Browser   # igual + abre navegador
#
# Flags: -PublicPort 8080 -LocalPort 3000 -ControlPort 9000 -Token abc123

[CmdletBinding()]
param(
  [switch]$Keep,
  [switch]$Browser,
  [int]$PublicPort  = 8080,
  [int]$LocalPort   = 3000,
  [int]$ControlPort = 9000,
  [string]$Token    = "abc123"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location $repoRoot
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

# Limpiar colgados previos
Get-NetTCPConnection -LocalPort $ControlPort,$PublicPort,$LocalPort -ErrorAction SilentlyContinue |
  ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
Start-Sleep -Milliseconds 600

Write-Host ""
Write-Host "=== Tunel end-to-end test ===" -ForegroundColor Cyan
Write-Host ""

# Build con go
Write-Host "[0/5] Build asegurado..." -ForegroundColor DarkGray
if (-not (Test-Path "tunels.exe"))     { go build -o tunels.exe     ./cmd/tunels     }
if (-not (Test-Path "tunelc.exe"))     { go build -o tunelc.exe     ./cmd/tunelc     }
if (-not (Test-Path "tunel-echo.exe")) { go build -o tunel-echo.exe ./cmd/tunel-echo }
if (-not (Test-Path "tunel-cert.exe")) { go build -o tunel-cert.exe ./cmd/tunel-cert }

# 1) certs
Write-Host "[1/5] Certificados..." -ForegroundColor Cyan
if (-not (Test-Path "certs\ca.crt")) {
  & ".\tunel-cert.exe" -out ".\certs" -hosts "127.0.0.1,localhost" | Out-Null
}
Write-Host "      OK" -ForegroundColor Green

$here = (Get-Location).Path

# 2) tunels en background
Write-Host "[2/5] tunels (server) en 127.0.0.1:$ControlPort ..." -ForegroundColor Cyan
$jbSrv = Start-Job -ScriptBlock {
  param($p)
  Set-Location $p
  & ".\tunels.exe" --bind "127.0.0.1:9000" --token "abc123" --cert "certs\server.crt" --key "certs\server.key" --allowed-ports "8080" --log-level info
} -ArgumentList $here
Start-Sleep -Seconds 1

# 3) tunel-echo (servicio local)
Write-Host "[3/5] tunel-echo (servicio LOCAL) en 127.0.0.1:$LocalPort ..." -ForegroundColor Cyan
$jbHttp = Start-Job -ScriptBlock {
  param($p, $port)
  Set-Location $p
  & ".\tunel-echo.exe" -listen "127.0.0.1:$port"
} -ArgumentList $here, $LocalPort
Start-Sleep -Milliseconds 600

# 4) tunelc cliente
Write-Host "[4/5] tunelc (cliente) -> public $PublicPort -> local 127.0.0.1:$LocalPort ..." -ForegroundColor Cyan
$jbCli = Start-Job -ScriptBlock {
  param($p, $pub, $local)
  Set-Location $p
  & ".\tunelc.exe" --server "127.0.0.1:9000" --token "abc123" --remote "$pub" --local "127.0.0.1:$local" --cacert "certs\ca.crt" --log-level info
} -ArgumentList $here, $PublicPort, $LocalPort
Start-Sleep -Seconds 2

# 5) curl
Write-Host "[5/5] Invocando http://127.0.0.1:$PublicPort/ ..." -ForegroundColor Cyan
$ok = $false
try {
  $r = Invoke-WebRequest -Uri "http://127.0.0.1:$PublicPort/" -UseBasicParsing -TimeoutSec 8
  Write-Host ""
  Write-Host "    HTTP STATUS: $($r.StatusCode)" -ForegroundColor Green
  Write-Host "    BODY:" -ForegroundColor Green
  $r.Content -split "`n" | ForEach-Object { Write-Host "    $_" -ForegroundColor White }
  Write-Host ""
  Write-Host "    >>> TUNEL FUNCIONA <<<" -ForegroundColor Green
  $ok = $true
} catch {
  Write-Host "    FALLO: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== Logs (server) ===" -ForegroundColor Yellow
Receive-Job $jbSrv -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "    $_" }
Write-Host "=== Logs (client) ===" -ForegroundColor Yellow
Receive-Job $jbCli -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "    $_" }

if ($Keep) {
  Write-Host ""
  Write-Host "Procesos corriendo. Puerto publico: http://127.0.0.1:$PublicPort/" -ForegroundColor Cyan
  Write-Host "Pulsa Enter para detener todo..."
  if ($Browser) { Start-Process "http://127.0.0.1:$PublicPort/" }
  [void](Read-Host)
}

# Limpieza final
Stop-Job $jbSrv, $jbCli, $jbHttp -ErrorAction SilentlyContinue
Remove-Job $jbSrv, $jbCli, $jbHttp -ErrorAction SilentlyContinue
Get-Process tunels,tunelc,tunel-echo -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Write-Host ""
Write-Host "Listo." -ForegroundColor Green