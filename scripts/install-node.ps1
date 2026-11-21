# proxygw 节点一键接入脚本（Windows / PowerShell）
#
# 用法（管理员 PowerShell）：
#   .\install-node.ps1 -Server https://gw.example.com:443 -Token <接入令牌> -Pin "sha256/..." `
#       -ClientId node-win-1 -Tags "cn-residential,telecom" -Alias "华东住宅节点"
#
# 可选：-Binary C:\path\to\proxygw-client.exe  使用本地二进制（默认从 DownloadBase 下载）
#       -NoService                             只安装与自检，不注册 Windows 服务（需要 NSSM）
# 说明：Token 只写入 %ProgramData%\proxygw\config.client.yaml（ACL 限制为管理员+服务账号）。
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Server,
    [Parameter(Mandatory = $true)][string]$Token,
    [string]$Pin = "",
    [string]$ClientId = "",
    [string]$Alias = "",
    [string]$Tags = "",
    [string]$Region = "",
    [string]$Transport = "auto",
    [int]$Planes = 2,
    [string]$Binary = "",
    [string]$DownloadBase = "https://downloads.example.invalid/proxygw",
    [string]$Version = "latest",
    [switch]$NoService
)

$ErrorActionPreference = "Stop"
$InstallDir = Join-Path $env:ProgramFiles "proxygw"
$ConfigDir = Join-Path $env:ProgramData "proxygw"
$StateDir = Join-Path $ConfigDir "state"
$ConfigPath = Join-Path $ConfigDir "config.client.yaml"
$Exe = Join-Path $InstallDir "proxygw-client.exe"

function Info($msg) { Write-Host "[proxygw] $msg" -ForegroundColor Cyan }
function Die($msg) { Write-Error "错误：$msg"; exit 1 }

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Die "请以管理员身份运行 PowerShell"
}

New-Item -ItemType Directory -Force -Path $InstallDir, $ConfigDir, $StateDir | Out-Null

if ([string]::IsNullOrWhiteSpace($Binary)) {
    $arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
    $Binary = Join-Path $env:TEMP "proxygw-client-windows-$arch.exe"
    $url = "$DownloadBase/$Version/proxygw-client-windows-$arch.exe"
    Info "下载 $url"
    try { Invoke-WebRequest -Uri $url -OutFile $Binary -UseBasicParsing -TimeoutSec 120 } catch {
        Die "下载失败：$($_.Exception.Message)；可用 -Binary 指定本地二进制"
    }
}
if (-not (Test-Path $Binary)) { Die "二进制不存在：$Binary" }

Info "安装二进制到 $InstallDir"
Copy-Item $Binary $Exe -Force
Unblock-File $Exe -ErrorAction SilentlyContinue

Info "写入配置 $ConfigPath"
$tagYaml = if ([string]::IsNullOrWhiteSpace($Tags)) { "[]" } else {
    "[" + (($Tags -split ",") | ForEach-Object { '"' + $_.Trim() + '"' }) -join ", " + "]"
}
$yaml = @"
server_url: "$Server"
token: "$Token"
client_id: "$ClientId"
alias: "$Alias"
tags: $tagYaml
region: "$Region"
transport: $Transport
planes: $Planes
state_dir: "$($StateDir -replace '\\','/')"
tls:
  mode: pin
  pin: "$Pin"
  pins: []
log:
  level: info
  format: json
"@
Set-Content -Path $ConfigPath -Value $yaml -Encoding UTF8
# 限制配置目录 ACL：仅 SYSTEM/Administrators/Users(读) 之外不放开
icacls $ConfigDir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "Users:(OI)(CI)RX" | Out-Null
icacls $StateDir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null

Info "配置校验"
& $Exe -config $ConfigPath -check-config
if ($LASTEXITCODE -ne 0) { Die "配置校验失败" }

$nssm = Get-Command nssm.exe -ErrorAction SilentlyContinue
if (-not $NoService -and $nssm) {
    Info "注册 Windows 服务 proxygw-client（NSSM）"
    & nssm.exe install proxygw-client $Exe | Out-Null
    & nssm.exe set proxygw-client AppParameters "-config `"$ConfigPath`"" | Out-Null
    & nssm.exe set proxygw-client AppDirectory $InstallDir | Out-Null
    & nssm.exe set proxygw-client AppStdout (Join-Path $ConfigDir "client.log") | Out-Null
    & nssm.exe set proxygw-client AppStderr (Join-Path $ConfigDir "client.err.log") | Out-Null
    & nssm.exe set proxygw-client Start SERVICE_AUTO_START | Out-Null
    & nssm.exe start proxygw-client | Out-Null
    Start-Sleep -Seconds 2
    Get-Service proxygw-client | Format-Table -AutoSize
} elseif (-not $NoService) {
    Info "未找到 nssm.exe；已跳过服务注册。可手动运行：`"$Exe`" -config `"$ConfigPath`""
} else {
    Info "已跳过服务注册。手动运行：`"$Exe`" -config `"$ConfigPath`""
}

Info "连通性自检（服务端 /healthz）"
$base = ($Server -replace '^wss://', 'https://' -replace '^ws://', 'http://') -replace '/tunnel/?$', ''
try {
    $resp = Invoke-WebRequest -Uri "$base/healthz" -UseBasicParsing -TimeoutSec 5
    Info "服务端健康：$($resp.StatusCode) $($resp.Content)"
} catch {
    Write-Warning "无法访问 $base/healthz（自签证书可加 -SkipCertificateCheck 重试）：$($_.Exception.Message)"
}

Write-Host @"

接入完成。请到服务端面板「节点」页确认节点在线，并核对出口 IP / 归属地。
排障顺序：防火墙（TCP+UDP 443）→ pin 指纹 → token 是否吊销 → 日志 $ConfigDir\client.err.log
"@ -ForegroundColor Green
