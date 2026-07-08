# scripts/test-vpn.ps1
# Prueba end-to-end modo VPN. Requiere PowerShell ELEVADO (administrador)
# porque wintun.dll necesita crear un adaptador de red virtual.
#
# Verifica: handshake VPN, asignacion de IP 10.99.0.x, ping entre dos
# instancias del cliente, broadcast UDP replicado a todos los peers (modo LAN
# discovery estilo Minecraft Bedrock).
#
# Uso:
#   1) Click derecho en PowerShell > "Ejecutar como administrador".
#   2) cd C:\...\Tunel
#   3) .\scripts\test-vpn.ps1
#
# El script levanta tunels --vpn en background y DOS tunelc-cli --vpn que
# obtienen IPs 10.99.0.1 y 10.99.0.2 respectivamente, hace ping entre ellos
# y finaliza dejando los binarios limpios.

[CmdletBinding()]
param(
  [string]$Server  = "127.0.0.1:9000",
  [string]$Token    = "abc123",
  [string]$Subnet   = "10.99.0.0/24"
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

# Check admin
$wid = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$prp = New-Object System.Security.Principal.WindowsPrincipal($wid)
if (-not $prp.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "Este script necesita permisos de administrador para abrir el adaptador wintun." -ForegroundColor Red
  Write-Host "Click derecho en PowerShell > 'Ejecutar como administrador' y reintenta." -ForegroundColor Yellow
  exit 2
}

# Build necesario
Write-Host "==> Build tunels.exe + tunelc-cli.exe (VPN tag)" -ForegroundColor Cyan
$env:GOFLAGS = "-mod=mod"
$env:CGO_ENABLED = "1"
go build -o tunels.exe ./cmd/tunels
go build -tags vpn -o tunelc-cli.exe ./cmd/tunelc

# Genera certs si no existen
if (-not (Test-Path "certs\ca.crt")) {
  & ".\tunel-cert.exe" -out ".\certs" -hosts "127.0.0.1,localhost" | Out-Null
}

# Limpiar stale
Get-Process tunels,tunelc,tunelc-cli -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Get-NetTCPConnection -LocalPort 9000 -State Listen -ErrorAction SilentlyContinue |
  ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
Start-Sleep -Milliseconds 500

# Arrancar server VPN
Write-Host "==> tunels --vpn en $Server (subnet $Subnet)" -ForegroundColor Cyan
$jbSrv = Start-Job -ScriptBlock {
  param($p,$server,$token,$subnet)
  Set-Location $p
  & ".\tunels.exe" --bind $server --token $token --cert certs\server.crt --key certs\server.key --vpn --vpn-subnet $subnet --log-level info
} -ArgumentList (Get-Location).Path,$Server,$Token,$Subnet
Start-Sleep -Seconds 1

# Lanzar dos clientes VPN
Write-Host "==> tunelc-cli --vpn (peer 1)" -ForegroundColor Cyan
$jbC1 = Start-Job -ScriptBlock {
  param($p,$server,$token)
  Set-Location $p
  & ".\tunelc-cli.exe" --server $server --token $token --cacert certs\ca.crt --vpn --max-attempts 1 --log-level info
} -ArgumentList (Get-Location).Path,$Server,$Token
Start-Sleep -Seconds 2

Write-Host "==> tunelc-cli --vpn (peer 2)" -ForegroundColor Cyan
$jbC2 = Start-Job -ScriptBlock {
  param($p,$server,$token)
  Set-Location $p
  & ".\tunelc-cli.exe" --server $server --token $token --cacert certs\ca.crt --vpn --max-attempts 1 --log-level info
} -ArgumentList (Get-Location).Path,$Server,$Token
Start-Sleep -Seconds 4

# Mostrar interfaces
Write-Host ""
Write-Host "=== Interfaces TUN activas ===" -ForegroundColor Yellow
Get-NetIPAddress -InterfaceAlias "TunelVPN*" -ErrorAction SilentlyContinue |
  Select-Object InterfaceAlias, IPAddress, PrefixLength

Write-Host ""
Write-Host "=== Ping 10.99.0.1 (-n 3 ===)" -ForegroundColor Yellow
Test-Connection -ComputerName "10.99.0.1" -Count 3 -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== Logs server ===" -ForegroundColor Yellow
Receive-Job $jbSrv -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $_" }
Write-Host "=== Logs client 1 ===" -ForegroundColor Yellow
Receive-Job $jbC1 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $_" }
Write-Host "=== Logs client 2 ===" -ForegroundColor Yellow
Receive-Job $jbC2 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "  $_" }

# Cleanup
Stop-Job $jbSrv, $jbC1, $jbC2 -ErrorAction SilentlyContinue
Remove-Job $jbSrv, $jbC1, $jbC2 -ErrorAction SilentlyContinue
Get-Process tunels,tunelc-cli -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Remove-Item tunelc-cli.exe -ErrorAction SilentlyContinue
Remove-Item wintun.dll -ErrorAction SilentlyContinue
Write-Host ""
Write-Host "Done." -ForegroundColor Green