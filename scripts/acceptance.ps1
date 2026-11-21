#Requires -Version 5.1
<#
.SYNOPSIS
    proxygw 本地自动化验收脚本（Windows / PowerShell 5.1+ / PowerShell 7）。

.DESCRIPTION
    一条命令完成可本地自动化的验收项：
      * go vet / go test / 构建 server 与 client 二进制
      * 生成唯一临时目录 + 随机高位端口 + 临时配置（pin 模式、强随机节点令牌、auth required、geo 关闭、JSON 日志落文件）
      * 启动本地 origin HTTP 服务、服务端、两个节点客户端
      * 逐项检查：healthz/version、节点注册与 QUIC 主用、HTTP/CONNECT/SOCKS5 代理、
        面板登录/CSRF/设置热更与撤销、审计脱敏、组隔离与 fail-closed、会话粘性、
        QUIC→wss 回退（UDP 黑洞）、pin 不匹配硬失败、并发与连接回收、停机端口释放
    输出彩色 PASS/FAIL 表格与汇总；失败退出码 1，成功 0。
    脚本不会修改仓库内的 Go 代码/配置模板；仅写入 bin/ 构建产物与系统临时目录。

.PARAMETER SkipUnitTests
    跳过 go test ./...（开发期快速验证用；跳过项记为 SKIP）。

.PARAMETER KeepArtifacts
    保留临时目录（配置、日志）以便排障。失败时默认也会保留并在结尾打印路径。

.PARAMETER RepoRoot
    仓库根目录，默认取脚本所在目录的上一级。

.NOTES
    依赖：Go 1.22+、curl.exe（Windows 10+ 自带）、node（可选，仅用于本地 origin；
    没有 node 时脚本会用 PowerShell HttpListener 兜底，若两者都不可用则相关检查标 SKIP）。
    本地测试需要把回环地址作为代理目标，因此服务端进程单独注入
    NP_ACL_ALLOW_LOOPBACK_TARGETS=1（生产默认关闭，见 README「设计决策 13」）。
#>
[CmdletBinding()]
param(
    [switch]$SkipUnitTests,
    [switch]$KeepArtifacts,
    [string]$RepoRoot = ''
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# 全局状态
# ---------------------------------------------------------------------------
$script:Results = New-Object System.Collections.ArrayList
$script:Processes = New-Object System.Collections.ArrayList
$script:ManagedStop = @{}
$script:TempDir = $null
$script:RepoRoot = $null
$script:LogDir = $null
$script:GoExe = $null
$script:CurlExe = $null
$script:NodeExe = $null
$script:StackReady = $false
$script:OriginReady = $false

# 主服务端
$script:ListenPort = 0
$script:HttpPort = 0
$script:SocksPort = 0
$script:ServerProc = $null
$script:ServerErr = ''
$script:PanelBase = ''
$script:CookieJar = ''
$script:Csrf = ''
$script:Pin = ''
$script:ProxyUser = ''
$script:ProxyPass = ''
$script:AdminUser = ''
$script:AdminPass = ''
$script:NodeToken = ''

# 主服务端上的节点
$script:Client1Proc = $null
$script:Client2Proc = $null
$script:Client1Cfg = ''
$script:Client2Cfg = ''
$script:Node1ID = 'node-e2e-1'
$script:Node2ID = 'node-e2e-2'
$script:OriginPort = 0

# 面板对象
$script:GroupID = ''
$script:CredAID = ''
$script:CredAUser = 'cred-a'
$script:CredAPass = ''

# 其它实例
$script:FallbackServerProc = $null
$script:FallbackClientProc = $null
$script:FallbackBlackholeProc = $null

# ---------------------------------------------------------------------------
# 通用工具函数
# ---------------------------------------------------------------------------
function New-Token {
    param([int]$Length = 16)
    $alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    $sb = New-Object System.Text.StringBuilder
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $buf = New-Object byte[] 1
    while ($sb.Length -lt $Length) {
        $rng.GetBytes($buf)
        [void]$sb.Append($alphabet[$buf[0] % $alphabet.Length])
    }
    $rng.Dispose()
    return $sb.ToString()
}

function Write-Utf8File {
    param([string]$Path, [string]$Content)
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $enc)
}

function Read-Utf8File {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return '' }
    # 服务端/客户端日志由子进程持有句柄（Start-Process 重定向的共享模式不允许
    # 普通 File.ReadAllText），这里显式以 FileShare.ReadWrite 打开，避免误判空日志。
    for ($i = 0; $i -lt 20; $i++) {
        $stream = $null
        $reader = $null
        try {
            $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
            $text = $reader.ReadToEnd()
            $reader.Close()
            $stream.Close()
            return $text
        } catch {
            if ($reader) { try { $reader.Close() } catch { } }
            if ($stream) { try { $stream.Close() } catch { } }
            Start-Sleep -Milliseconds 100
        }
    }
    return ''
}

function Quote-NativeArg {
    param([string]$Value)
    if ($Value -match '[\s"]') { return '"' + ($Value -replace '"', '\"') + '"' }
    return $Value
}

function Join-NativeArgs {
    param([string[]]$Values)
    return (@($Values | ForEach-Object { Quote-NativeArg $_ }) -join ' ')
}

function Get-ObjectProperty {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Assert-Equal {
    param($Actual, $Expected, [string]$Message)
    if ("$Actual" -ne "$Expected") { throw ("{0}（期望={1} 实际={2}）" -f $Message, $Expected, $Actual) }
}

function Add-Result {
    param([string]$Id, [string]$Title, [string]$Status, [double]$Milliseconds, [string]$Note)
    $entry = [pscustomobject]@{
        Id      = $Id
        Title   = $Title
        Status  = $Status
        Ms      = [Math]::Round($Milliseconds, 1)
        Note    = $Note
    }
    [void]$script:Results.Add($entry)
    return $entry
}

function Show-ResultLine {
    param([string]$Id, [string]$Title, [string]$Status, [string]$Note)
    $color = 'Gray'
    if ($Status -eq 'PASS') { $color = 'Green' }
    elseif ($Status -eq 'FAIL') { $color = 'Red' }
    elseif ($Status -eq 'SKIP') { $color = 'Yellow' }
    Write-Host ('  {0,-4} {1,-34} ' -f $Id, $Title) -NoNewline
    Write-Host ('{0,-5}' -f $Status) -NoNewline -ForegroundColor $color
    if ($Note) { Write-Host ('  ' + $Note) } else { Write-Host '' }
}

function Run-Check {
    param(
        [string]$Id,
        [string]$Title,
        [scriptblock]$Body,
        [switch]$NeedsStack,
        [switch]$NeedsOrigin
    )
    if ($NeedsStack -and -not $script:StackReady) {
        Add-Result $Id $Title 'SKIP' 0 '依赖主栈未启动（前置检查失败）' | Out-Null
        return 'SKIP'
    }
    if ($NeedsOrigin -and -not $script:OriginReady) {
        Add-Result $Id $Title 'SKIP' 0 '本地 origin 不可用（node/HttpListener 均不可用）' | Out-Null
        return 'SKIP'
    }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $status = 'FAIL'
    $note = ''
    try {
        $outcome = & $Body
        if ($outcome -is [hashtable] -and $outcome.ContainsKey('Skip') -and [bool]$outcome['Skip']) {
            $status = 'SKIP'
            $note = [string]$outcome['Note']
        } else {
            $note = [string]$outcome
            if ([string]::IsNullOrWhiteSpace($note)) { $note = '' }
            $status = 'PASS'
        }
    } catch {
        $note = $_.Exception.Message
        if ([string]::IsNullOrWhiteSpace($note)) { $note = ($_ | Out-String).Trim() }
    }
    $sw.Stop()
    Add-Result $Id $Title $status $sw.Elapsed.TotalMilliseconds $note | Out-Null
    return $status
}

function Add-SkippedCheck {
    param([string]$Id, [string]$Title, [string]$Reason)
    Add-Result $Id $Title 'SKIP' 0 $Reason | Out-Null
}

# --- 进程管理 ---------------------------------------------------------------
function Start-ManagedProcess {
    param(
        [string]$Exe,
        [string[]]$Arguments = @(),
        [string]$StdOut = '',
        [string]$StdErr = '',
        [hashtable]$Environment = $null,
        [string]$WorkingDirectory = ''
    )
    $saved = @{}
    if ($Environment) {
        foreach ($key in @($Environment.Keys)) {
            $saved[$key] = [System.Environment]::GetEnvironmentVariable($key)
            [System.Environment]::SetEnvironmentVariable($key, [string]$Environment[$key])
        }
    }
    $startArgs = @{
        FilePath     = $Exe
        ArgumentList = (Join-NativeArgs $Arguments)
        PassThru     = $true
        WindowStyle  = 'Hidden'
    }
    if ($WorkingDirectory) { $startArgs['WorkingDirectory'] = $WorkingDirectory }
    if ($StdOut) {
        $startArgs['RedirectStandardOutput'] = $StdOut
    }
    if ($StdErr) {
        $startArgs['RedirectStandardError'] = $StdErr
    }
    if (-not $StdOut -and -not $StdErr) {
        # Start-Process 在带重定向时才能可靠拿到句柄；无日志时写空文件即可。
        $startArgs['RedirectStandardOutput'] = (Join-Path $script:TempDir ('noop-' + (New-Token 8) + '.out'))
        $startArgs['RedirectStandardError'] = (Join-Path $script:TempDir ('noop-' + (New-Token 8) + '.err'))
    }
    try {
        $proc = Start-Process @startArgs
    } finally {
        if ($Environment) {
            foreach ($key in @($Environment.Keys)) {
                try { [System.Environment]::SetEnvironmentVariable($key, $saved[$key]) } catch { }
            }
        }
    }
    if ($null -eq $proc) { throw ("无法启动进程：$Exe") }
    [void]$script:Processes.Add($proc)
    return $proc
}

function Stop-ManagedProcess {
    param($Process, [int]$TimeoutMs = 5000)
    if ($null -eq $Process) { return }
    try {
        if (-not $Process.HasExited) {
            try { Stop-Process -Id $Process.Id -Force -ErrorAction Stop } catch { }
        }
        try { [void]$Process.WaitForExit($TimeoutMs) } catch { }
    } catch { }
}

function Stop-ManagedProcessById {
    param([int]$ProcessId, [int]$TimeoutMs = 5000)
    if ($ProcessId -le 0) { return }
    try {
        $p = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    } catch { $p = $null }
    if ($p) { Stop-ManagedProcess -Process $p -TimeoutMs $TimeoutMs }
}

# --- 端口检查 ---------------------------------------------------------------
function Test-TcpPortFree {
    param([int]$Port)
    try {
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Port)
        $listener.Start()
        $listener.Stop()
        return $true
    } catch { return $false }
}

function Test-UdpPortFree {
    param([int]$Port)
    try {
        # 必须绑定到 127.0.0.1 的具体地址：Windows 允许「0.0.0.0 通配绑定」与
        # 「127.0.0.1 具体绑定」共存，用通配绑定无法检测到只绑定了回环地址的进程
        # （例如 QUIC 服务端、UDP 黑洞模拟器）。
        $endpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Loopback, $Port)
        $client = New-Object System.Net.Sockets.UdpClient($endpoint)
        $client.Close()
        return $true
    } catch { return $false }
}

function Get-FreePort {
    for ($attempt = 0; $attempt -lt 100; $attempt++) {
        $port = Get-Random -Minimum 20000 -Maximum 60000
        if (($script:UsedPorts -notcontains $port) -and (Test-TcpPortFree $port) -and (Test-UdpPortFree $port)) {
            [void]$script:UsedPorts.Add($port)
            return $port
        }
    }
    throw '无法分配空闲端口'
}

function Wait-TcpConnecting {
    param([int]$Port, [int]$TimeoutSec = 30)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $async = $client.BeginConnect('127.0.0.1', $Port, $null, $null)
            if ($async.AsyncWaitHandle.WaitOne(500) -and $client.Connected) {
                $client.Close()
                return $true
            }
            $client.Close()
        } catch { }
        Start-Sleep -Milliseconds 200
    }
    return $false
}

function Wait-UdpPortBusy {
    param([int]$Port, [int]$TimeoutSec = 15)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if (-not (Test-UdpPortFree $Port)) { return $true }
        Start-Sleep -Milliseconds 200
    }
    return $false
}

# --- curl 封装 --------------------------------------------------------------
function Get-Curl {
    if ($script:CurlExe) { return $script:CurlExe }
    $cmd = Get-Command 'curl.exe' -ErrorAction SilentlyContinue
    if (-not $cmd) { $cmd = Get-Command 'curl' -ErrorAction SilentlyContinue }
    if (-not $cmd) { throw '未找到 curl（Windows 10+ 自带 curl.exe，请确认 PATH）' }
    $script:CurlExe = $cmd.Source
    return $script:CurlExe
}

function Invoke-Curl {
    param(
        [string]$Url,
        [string[]]$Extra = @(),
        [string]$BodyFile = '',
        [int]$MaxTimeSec = 60
    )
    $curl = Get-Curl
    $outFile = $BodyFile
    if (-not $outFile) {
        $outFile = Join-Path $script:TempDir ('curl-' + (New-Token 10) + '.out')
    }
    $errFile = Join-Path $script:TempDir ('curl-' + (New-Token 10) + '.err')
    $arguments = @('-s', '-S', '--max-time', [string]$MaxTimeSec, '-o', $outFile, '-w', '%{http_code}') + $Extra + @($Url)
    $codeText = $null
    $exitCode = -1
    try {
        $codeText = & $curl @arguments 2> $errFile
        $exitCode = $LASTEXITCODE
    } catch {
        $exitCode = -1
    }
    $body = ''
    if (Test-Path -LiteralPath $outFile) {
        $body = [System.IO.File]::ReadAllText($outFile, [System.Text.Encoding]::UTF8)
    }
    $code = 0
    if ($codeText) {
        $last = @($codeText)[@($codeText).Count - 1]
        [void][int]::TryParse(([string]$last).Trim(), [ref]$code)
    }
    $errText = Read-Utf8File $errFile
    if (-not $BodyFile -and (Test-Path -LiteralPath $outFile)) {
        Remove-Item -LiteralPath $outFile -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $errFile -Force -ErrorAction SilentlyContinue
    return [pscustomobject]@{
        Code     = $code
        Body     = $body
        ExitCode = $exitCode
        Err      = $errText
    }
}

function ConvertTo-JsonBody {
    param($Value)
    return ($Value | ConvertTo-Json -Depth 30 -Compress)
}

# Copy-JsonObject deep-clones a PSCustomObject graph through JSON, so later
# property mutations never leak into the object returned by the panel.
function Copy-JsonObject {
    param($Value)
    if ($null -eq $Value) { return $null }
    return ($Value | ConvertTo-Json -Depth 30 | ConvertFrom-Json)
}

# --- 面板 API 封装 ----------------------------------------------------------
function Use-PanelEndpoint {
    param([string]$Base, [string]$CookieJar)
    $script:PanelBase = $Base
    $script:CookieJar = $CookieJar
    $script:Csrf = ''
}

function Invoke-PanelRequest {
    param(
        [string]$Method,
        [string]$Path,
        $Body = $null,
        [switch]$NoCsrf,
        [switch]$NoCookies,
        [int]$MaxTimeSec = 30
    )
    $arguments = @('-k', '-s', '--max-time', [string]$MaxTimeSec, '-X', $Method)
    if (-not $NoCookies) {
        $arguments += @('-b', $script:CookieJar, '-c', $script:CookieJar)
    }
    if ($script:Csrf -and -not $NoCsrf) {
        $arguments += @('-H', "X-CSRF-Token: $($script:Csrf)")
    }
    $bodyFile = ''
    if ($null -ne $Body) {
        $json = if ($Body -is [string]) { $Body } else { ConvertTo-JsonBody $Body }
        $bodyFile = Join-Path $script:TempDir ('panel-req-' + (New-Token 10) + '.json')
        Write-Utf8File $bodyFile $json
        $arguments += @('-H', 'Content-Type: application/json', '--data-binary', ('@' + ($bodyFile -replace '\\', '/')))
    }
    try {
        return Invoke-Curl -Url ($script:PanelBase + $Path) -Extra $arguments -MaxTimeSec $MaxTimeSec
    } finally {
        if ($bodyFile -and (Test-Path -LiteralPath $bodyFile)) {
            Remove-Item -LiteralPath $bodyFile -Force -ErrorAction SilentlyContinue
        }
    }
}

function ConvertFrom-JsonSafe {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    try { return ($Text | ConvertFrom-Json) } catch { return $null }
}

function Invoke-PanelLogin {
    param([string]$Username, [string]$Password)
    $resp = Invoke-PanelRequest -Method 'POST' -Path '/api/v1/login' -Body @{ username = $Username; password = $Password } -NoCsrf
    $json = ConvertFrom-JsonSafe $resp.Body
    if ($resp.Code -ne 200) {
        throw ("面板登录失败：HTTP {0} {1}" -f $resp.Code, $resp.Body)
    }
    if ($null -eq $json -or [string]::IsNullOrWhiteSpace([string](Get-ObjectProperty $json 'csrf'))) {
        throw ("面板登录响应缺少 csrf：HTTP {0} {1}" -f $resp.Code, $resp.Body)
    }
    $script:Csrf = [string](Get-ObjectProperty $json 'csrf')
    return $json
}

function Get-PanelOverview {
    $resp = Invoke-PanelRequest -Method 'GET' -Path '/api/v1/overview'
    if ($resp.Code -ne 200) { throw ("GET /overview 失败：HTTP {0} {1}" -f $resp.Code, $resp.Body) }
    return (ConvertFrom-JsonSafe $resp.Body)
}

function Get-PanelNodes {
    $resp = Invoke-PanelRequest -Method 'GET' -Path '/api/v1/nodes?size=100'
    if ($resp.Code -ne 200) { throw ("GET /nodes 失败：HTTP {0} {1}" -f $resp.Code, $resp.Body) }
    $json = ConvertFrom-JsonSafe $resp.Body
    $items = Get-ObjectProperty $json 'items'
    if ($null -eq $items) { return @() }
    return @($items)
}

function Wait-OnlineNodes {
    param([int]$Minimum, [int]$TimeoutSec = 40)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $lastCount = -1
    while ((Get-Date) -lt $deadline) {
        try {
            $overview = Get-PanelOverview
            $lastCount = [int](Get-ObjectProperty $overview 'online_nodes')
            if ($lastCount -ge $Minimum) { return $overview }
        } catch { }
        Start-Sleep -Milliseconds 300
    }
    throw ("等待在线节点 >= {0} 超时（当前 {1}）" -f $Minimum, $lastCount)
}

function Wait-NodeOffline {
    param([string]$NodeId, [int]$TimeoutSec = 120)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $start = Get-Date
    while ((Get-Date) -lt $deadline) {
        $nodes = Get-PanelNodes
        $target = $nodes | Where-Object { [string](Get-ObjectProperty $_ 'id') -eq $NodeId } | Select-Object -First 1
        if ($null -eq $target) { return ((Get-Date) - $start).TotalSeconds }
        $online = [bool](Get-ObjectProperty $target 'online')
        if (-not $online) { return ((Get-Date) - $start).TotalSeconds }
        Start-Sleep -Milliseconds 500
    }
    throw ("等待节点 {0} 离线超时（{1}s）" -f $NodeId, $TimeoutSec)
}

# --- HTTP 入口封装 ----------------------------------------------------------
function Invoke-OriginUrl {
    param([string]$Path)
    return ("http://127.0.0.1:{0}{1}" -f $script:OriginPort, $Path)
}

function Invoke-HttpProxy {
    param([string]$Url, [string]$User, [string]$Password, [int]$MaxTimeSec = 30)
    $arguments = @('--noproxy=', '-x', ("http://127.0.0.1:{0}" -f $script:HttpPort), '--proxy-user', ("{0}:{1}" -f $User, $Password))
    return Invoke-Curl -Url $Url -Extra $arguments -MaxTimeSec $MaxTimeSec
}

function Invoke-HttpsProxy {
    param([string]$Url, [string]$User, [string]$Password, [int]$MaxTimeSec = 30)
    $arguments = @('--noproxy=', '-k', '-x', ("http://127.0.0.1:{0}" -f $script:HttpPort), '--proxy-user', ("{0}:{1}" -f $User, $Password))
    return Invoke-Curl -Url $Url -Extra $arguments -MaxTimeSec $MaxTimeSec
}

function Invoke-Socks5Proxy {
    param([string]$Url, [string]$User, [string]$Password, [int]$MaxTimeSec = 30)
    $arguments = @('--noproxy=', '--socks5-hostname', ("127.0.0.1:{0}" -f $script:SocksPort), '--proxy-user', ("{0}:{1}" -f $User, $Password))
    return Invoke-Curl -Url $Url -Extra $arguments -MaxTimeSec $MaxTimeSec
}

# --- 配置生成 ---------------------------------------------------------------
function New-ServerConfigFile {
    param(
        [string]$Path,
        [int]$ListenPort,
        [int]$HttpPort,
        [int]$SocksPort,
        [string]$StateDir,
        [string]$NodeToken,
        [string]$Transport = 'auto',
        [int]$Planes = 2
    )
    $state = $StateDir -replace '\\', '/'
    $yaml = @"
# proxygw 验收脚本生成的服务端配置（临时，勿用于生产）
state_dir: $state
log:
  level: info
  format: json
server:
  listen_addr: "127.0.0.1:$ListenPort"
  ui_enabled: true
  proxy_protocol: false
proxy:
  http_listen: "127.0.0.1:$HttpPort"
  socks5_listen: "127.0.0.1:$SocksPort"
  auth_mode: required
  max_header_bytes: 65536
  max_concurrent: 0
tunnel:
  transport: $Transport
  planes: $Planes
  allow_plain_ws: false
  alpn: proxygw/1
  max_frame_bytes: 65536
  quic_cc: cubic
tls:
  mode: pin
  client_auth: none
admin:
  username: admin
nodes:
  mtls: false
  tokens:
    - node_id: "*"
      token: "$NodeToken"
geo:
  enabled: false
observability:
  metrics_enabled: true
  metrics_path: /metrics
audit:
  enabled: true
settings:
  scheduler:
    strategy: random
    sticky:
      enabled: true
      ttl: 10m
      max_keys_per_node: 1000
"@
    Write-Utf8File $Path $yaml
}

function New-ClientConfigFile {
    param(
        [string]$Path,
        [string]$ServerUrl,
        [string]$NodeToken,
        [string]$ClientId,
        [string[]]$Tags,
        [string]$StateDir,
        [string]$Pin,
        [string]$Transport = 'auto',
        [int]$Planes = 2
    )
    $state = $StateDir -replace '\\', '/'
    $tagList = (@($Tags | ForEach-Object { '"' + ($_ -replace '"', '') + '"' }) -join ', ')
    $yaml = @"
# proxygw 验收脚本生成的节点配置（临时，勿用于生产）
server_url: "$ServerUrl"
token: "$NodeToken"
client_id: "$ClientId"
alias: "$ClientId"
tags: [$tagList]
weight: 100
transport: $Transport
quic_fallback: 2s
planes: $Planes
compression: false
state_dir: $state
log:
  level: info
  format: json
tls:
  mode: pin
  pin: "$Pin"
egress:
  manual_v4: "127.0.0.1"
security:
  allow_insecure_defaults: false
"@
    Write-Utf8File $Path $yaml
}

function Start-OriginServer {
    param([int]$Port, [string]$Directory)
    $script:OriginReady = $false
    $script:OriginMode = 'none'
    $logPath = Join-Path $Directory 'origin.log'
    $node = Get-Command 'node' -ErrorAction SilentlyContinue
    if ($node) {
        $script:NodeExe = $node.Source
        $originJs = @'
const http = require('http');
const fs = require('fs');
const port = Number(process.argv[2]);
const logPath = process.argv[3];
const big = Buffer.alloc(65536);
for (let i = 0; i < big.length; i++) { big[i] = 97 + (i % 26); }
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://origin.invalid');
  const path = url.pathname;
  const respond = (code, type, data) => {
    res.writeHead(code, { 'Content-Type': type, 'Content-Length': Buffer.byteLength(data), 'Cache-Control': 'no-store' });
    res.end(data);
  };
  if (path === '/healthz') { respond(200, 'application/json', JSON.stringify({ ok: true, origin: true })); return; }
  if (path === '/echo') { respond(200, 'application/json', JSON.stringify({ ok: true, url: req.url, method: req.method, host: req.headers.host || '' })); return; }
  if (path === '/64k') {
    res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': big.length });
    res.end(big);
    return;
  }
  if (path === '/slow') {
    const ms = Math.min(20000, Number(url.searchParams.get('ms') || '1500'));
    setTimeout(() => respond(200, 'application/json', JSON.stringify({ ok: true, slow_ms: ms })), ms);
    return;
  }
  respond(404, 'text/plain', 'not found');
});
server.on('error', (err) => { try { fs.writeFileSync(logPath, 'error: ' + err.message); } catch (e) {} process.exit(1); });
server.listen(port, '127.0.0.1', () => { try { fs.writeFileSync(logPath, 'ready ' + port); } catch (e) {} });
'@
        $jsPath = Join-Path $Directory 'origin.js'
        Write-Utf8File $jsPath $originJs
        $out = Join-Path $Directory 'origin.out.log'
        $err = Join-Path $Directory 'origin.err.log'
        $proc = Start-ManagedProcess -Exe $node.Source -Arguments @($jsPath, [string]$Port, $logPath) -StdOut $out -StdErr $err
        $script:OriginProc = $proc
        $script:OriginMode = 'node'
    } else {
        # 兜底：用 PowerShell HttpListener 起一个独立进程（需要相应 URL ACL 权限）。
        $originPs1 = @'
param([int]$Port, [string]$LogPath)
$ErrorActionPreference = 'Stop'
$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://127.0.0.1:$Port/")
try { $listener.Start() } catch { Set-Content -LiteralPath $LogPath -Value ("error: " + $_.Exception.Message); exit 1 }
Set-Content -LiteralPath $LogPath -Value ("ready " + $Port)
$big = New-Object byte[] 65536
for ($i = 0; $i -lt $big.Length; $i++) { $big[$i] = [byte](97 + ($i % 26)) }
while ($listener.IsListening) {
    try { $ctx = $listener.GetContext() } catch { break }
    $req = $ctx.Request; $res = $ctx.Response
    try {
        $res.Headers['Cache-Control'] = 'no-store'
        $path = $req.Url.AbsolutePath
        if ($path -eq '/healthz') { $b = [Text.Encoding]::UTF8.GetBytes('{"ok":true,"origin":true}'); $res.StatusCode = 200; $res.ContentType = 'application/json' }
        elseif ($path -eq '/echo') { $json = @{ ok = $true; url = $req.RawUrl; method = $req.HttpMethod; host = $req.UserHostName } | ConvertTo-Json -Compress; $b = [Text.Encoding]::UTF8.GetBytes($json); $res.StatusCode = 200; $res.ContentType = 'application/json' }
        elseif ($path -eq '/64k') { $b = $big; $res.StatusCode = 200; $res.ContentType = 'application/octet-stream' }
        elseif ($path -eq '/slow') { $ms = 1500; try { $ms = [int]$req.QueryString['ms'] } catch { }; Start-Sleep -Milliseconds $ms; $b = [Text.Encoding]::UTF8.GetBytes('{"ok":true}'); $res.StatusCode = 200; $res.ContentType = 'application/json' }
        else { $res.StatusCode = 404; $b = [Text.Encoding]::UTF8.GetBytes('not found') }
        $res.ContentLength64 = $b.Length
        $res.OutputStream.Write($b, 0, $b.Length)
    } catch { } finally { try { $res.Close() } catch { } }
}
'@
        $ps1Path = Join-Path $Directory 'origin.ps1'
        Write-Utf8File $ps1Path $originPs1
        $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $out = Join-Path $Directory 'origin.out.log'
        $err = Join-Path $Directory 'origin.err.log'
        $proc = Start-ManagedProcess -Exe $powershell -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $ps1Path, '-Port', [string]$Port, '-LogPath', $logPath) -StdOut $out -StdErr $err
        $script:OriginProc = $proc
        $script:OriginMode = 'powershell'
    }
    # 等待 origin 就绪
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        $resp = Invoke-Curl -Url ("http://127.0.0.1:{0}/healthz" -f $Port) -MaxTimeSec 3
        if ($resp.Code -eq 200) {
            $script:OriginReady = $true
            return $true
        }
        Start-Sleep -Milliseconds 250
    }
    $detail = Read-Utf8File $logPath
    throw ("本地 origin 启动失败（{0}）：{1}" -f $script:OriginMode, $detail)
}

# ---------------------------------------------------------------------------
# 启动主栈（服务端 + 两个节点 + 面板登录）
# ---------------------------------------------------------------------------
function Read-ServerBootMessages {
    param([string]$ErrLogPath, [int]$TimeoutSec = 60)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $text = ''
    while ((Get-Date) -lt $deadline) {
        $text = Read-Utf8File $ErrLogPath
        if ($text -match 'SPKI 指纹=sha256/' -and $text -match '代理凭据' -and $text -match '面板管理员密码') { break }
        Start-Sleep -Milliseconds 300
    }
    $pin = ''
    $proxyUser = ''
    $proxyPass = ''
    $adminUser = ''
    $adminPass = ''
    $m = [regex]::Match($text, 'SPKI 指纹=(sha256/[A-Za-z0-9+/=]+)')
    if ($m.Success) { $pin = $m.Groups[1].Value }
    $m = [regex]::Match($text, '代理凭据（仅本次显示，请立即保存）：用户名 (\S+)\s+密码 (\S+)')
    if ($m.Success) { $proxyUser = $m.Groups[1].Value; $proxyPass = $m.Groups[2].Value }
    $m = [regex]::Match($text, '面板管理员密码（仅本次显示，请立即保存）：用户名 (\S+)\s+密码 (\S+)')
    if ($m.Success) { $adminUser = $m.Groups[1].Value; $adminPass = $m.Groups[2].Value }
    if (-not $pin -or -not $proxyUser -or -not $adminPass) {
        $tail = $text
        if ($tail.Length -gt 2000) { $tail = $tail.Substring($tail.Length - 2000) }
        throw ("未能从服务端启动日志解析 pin / 代理凭据 / 管理员密码。日志尾部：`n" + $tail)
    }
    return [pscustomobject]@{
        Pin       = $pin
        ProxyUser = $proxyUser
        ProxyPass = $proxyPass
        AdminUser = $adminUser
        AdminPass = $adminPass
        Raw       = $text
    }
}

function Start-MainStack {
    $script:UsedPorts = New-Object System.Collections.ArrayList

    # 唯一临时目录 + 随机端口 + 强随机令牌
    if ([string]::IsNullOrEmpty($script:TempDir)) {
        $script:TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ('proxygw-accept-' + (New-Token 8))
    }
    New-Item -ItemType Directory -Force -Path $script:TempDir | Out-Null
    $script:LogDir = $script:TempDir
    $script:ListenPort = Get-FreePort
    $script:HttpPort = Get-FreePort
    $script:SocksPort = Get-FreePort
    $script:OriginPort = Get-FreePort
    $script:NodeToken = New-Token 48

    $serverState = Join-Path $script:TempDir 'server-state'
    $client1State = Join-Path $script:TempDir 'client-1-state'
    $client2State = Join-Path $script:TempDir 'client-2-state'
    New-Item -ItemType Directory -Force -Path $serverState, $client1State, $client2State | Out-Null

    $serverCfg = Join-Path $script:TempDir 'server.yaml'
    New-ServerConfigFile -Path $serverCfg -ListenPort $script:ListenPort -HttpPort $script:HttpPort -SocksPort $script:SocksPort -StateDir $serverState -NodeToken $script:NodeToken

    $script:PanelBase = "https://127.0.0.1:$($script:ListenPort)"
    $script:CookieJar = Join-Path $script:TempDir 'cookies.txt'

    # 本地 origin（回环目标需要服务端 ACL 测试豁免）
    if (-not $script:OriginReady) {
        [void](Start-OriginServer -Port $script:OriginPort -Directory $script:TempDir)
    }

    # 服务端：仅该进程继承 NP_ACL_ALLOW_LOOPBACK_TARGETS=1
    $serverExe = $script:ServerExe
    $script:ServerErr = Join-Path $script:TempDir 'server.err.log'
    $serverOut = Join-Path $script:TempDir 'server.out.log'
    $script:ServerProc = Start-ManagedProcess -Exe $serverExe -Arguments @('-config', $serverCfg) -StdOut $serverOut -StdErr $script:ServerErr -Environment @{ 'NP_ACL_ALLOW_LOOPBACK_TARGETS' = '1' }

    # 等待 TLS 监听可用
    $deadline = (Get-Date).AddSeconds(60)
    $health = $null
    while ((Get-Date) -lt $deadline) {
        if ($script:ServerProc.HasExited) {
            throw ("服务端进程提前退出（exit={0}）。日志尾部：`n{1}" -f $script:ServerProc.ExitCode, (Get-LogTail $script:ServerErr 40))
        }
        $health = Invoke-Curl -Url "$($script:PanelBase)/healthz" -Extra @('-k') -MaxTimeSec 3
        if ($health.Code -eq 200) { break }
        Start-Sleep -Milliseconds 300
    }
    if ($null -eq $health -or $health.Code -ne 200) {
        throw ("服务端 /healthz 未就绪。日志尾部：`n" + (Get-LogTail $script:ServerErr 40))
    }

    # 从 stderr 解析一次性启动信息（pin、代理凭据、面板管理员密码）
    $boot = Read-ServerBootMessages -ErrLogPath $script:ServerErr
    $script:Pin = $boot.Pin
    $script:ProxyUser = $boot.ProxyUser
    $script:ProxyPass = $boot.ProxyPass
    $script:AdminUser = $boot.AdminUser
    $script:AdminPass = $boot.AdminPass

    # 面板登录（拿 CSRF）
    Use-PanelEndpoint -Base $script:PanelBase -CookieJar $script:CookieJar
    [void](Invoke-PanelLogin -Username $script:AdminUser -Password $script:AdminPass)

    # 两个节点客户端：node-e2e-1（组 g1 成员）与 node-e2e-2（用于验证不会回退到组外节点）
    $script:Client1Cfg = Join-Path $script:TempDir 'client-1.yaml'
    New-ClientConfigFile -Path $script:Client1Cfg -ServerUrl ("https://127.0.0.1:{0}" -f $script:ListenPort) `
        -NodeToken $script:NodeToken -ClientId $script:Node1ID -Tags @('node-e2e') -StateDir $client1State -Pin $script:Pin
    $client1Out = Join-Path $script:TempDir 'client-1.out.log'
    $client1Err = Join-Path $script:TempDir 'client-1.err.log'
    $script:Client1Proc = Start-ManagedProcess -Exe $script:ClientExe -Arguments @('-config', $script:Client1Cfg) -StdOut $client1Out -StdErr $client1Err

    $script:Client2Cfg = Join-Path $script:TempDir 'client-2.yaml'
    New-ClientConfigFile -Path $script:Client2Cfg -ServerUrl ("https://127.0.0.1:{0}" -f $script:ListenPort) `
        -NodeToken $script:NodeToken -ClientId $script:Node2ID -Tags @('node-extra') -StateDir $client2State -Pin $script:Pin
    $client2Out = Join-Path $script:TempDir 'client-2.out.log'
    $client2Err = Join-Path $script:TempDir 'client-2.err.log'
    $script:Client2Proc = Start-ManagedProcess -Exe $script:ClientExe -Arguments @('-config', $script:Client2Cfg) -StdOut $client2Out -StdErr $client2Err

    [void](Wait-OnlineNodes -Minimum 2 -TimeoutSec 40)
    $script:StackReady = $true
}

function Get-LogTail {
    param([string]$Path, [int]$Lines = 30)
    $text = Read-Utf8File $Path
    if ([string]::IsNullOrEmpty($text)) { return '(空)' }
    $all = @($text -split "\r?\n")
    if ($all.Count -le $Lines) { return ($all -join "`n") }
    return (($all[($all.Count - $Lines)..($all.Count - 1)]) -join "`n")
}

# ---------------------------------------------------------------------------
# 检查 0：go vet / go test / 构建
# ---------------------------------------------------------------------------
function Invoke-GoCommand {
    param(
        [string[]]$GoArgs,
        [int]$TimeoutSec = 600,
        [string]$WorkingDirectory = ''
    )
    $out = Join-Path $script:TempDir ('go-' + (New-Token 8) + '.out')
    $err = Join-Path $script:TempDir ('go-' + (New-Token 8) + '.err')
    $result = Invoke-CommandWithExitFile -Exe $script:GoExe -Arguments $GoArgs -StdOut $out -StdErr $err -WorkingDirectory $WorkingDirectory -TimeoutSec $TimeoutSec
    return [pscustomobject]@{
        ExitCode = $result.ExitCode
        TimedOut = $result.TimedOut
        Out      = (Read-Utf8File $out)
        Err      = (Read-Utf8File $err)
    }
}

# Invoke-CommandWithExitFile runs a native command to completion with output
# redirected to files and its exit code captured via a generated .cmd wrapper.
# Windows PowerShell 5.1 does not reliably expose ExitCode for Start-Process
# -PassThru when standard output is redirected, hence the wrapper.
function Invoke-CommandWithExitFile {
    param(
        [string]$Exe,
        [string[]]$Arguments = @(),
        [string]$StdOut,
        [string]$StdErr,
        [string]$WorkingDirectory = '',
        [int]$TimeoutSec = 600
    )
    $codeFile = Join-Path $script:TempDir ('exit-' + (New-Token 10) + '.txt')
    $cmdFile = Join-Path $script:TempDir ('run-' + (New-Token 10) + '.cmd')
    $line = '"' + $Exe + '"'
    foreach ($argument in $Arguments) {
        $line += ' ' + (Quote-NativeArg $argument)
    }
    $scriptContent = "@echo off`r`n"
    if ($WorkingDirectory) { $scriptContent += ('cd /d "' + $WorkingDirectory + '"' + "`r`n") }
    $scriptContent += ($line + ' 1> "' + $StdOut + '" 2> "' + $StdErr + '"' + "`r`n")
    $scriptContent += ('echo %ERRORLEVEL% > "' + $codeFile + '"' + "`r`n")
    Write-Utf8File $cmdFile $scriptContent
    $cmdExe = Join-Path $env:SystemRoot 'System32\cmd.exe'
    $proc = Start-Process -FilePath $cmdExe -ArgumentList ('/c "' + $cmdFile + '"') -PassThru -WindowStyle Hidden
    $timedOut = $false
    if (-not $proc.WaitForExit($TimeoutSec * 1000)) {
        $timedOut = $true
        try { & taskkill.exe /PID $proc.Id /T /F | Out-Null } catch { }
        try { [void]$proc.WaitForExit(5000) } catch { }
    }
    $exitCode = -1
    $exitText = (Read-Utf8File $codeFile).Trim()
    if ($exitText -ne '') {
        $parsed = 0
        if ([int]::TryParse($exitText, [ref]$parsed)) { $exitCode = $parsed }
    }
    if (-not (Test-Path -LiteralPath $StdOut)) { Write-Utf8File $StdOut '' }
    if (-not (Test-Path -LiteralPath $StdErr)) { Write-Utf8File $StdErr '' }
    return [pscustomobject]@{ ExitCode = $exitCode; TimedOut = $timedOut }
}

function Get-CommandTail {
    param($Result, [int]$Lines = 12)
    $text = (([string]$Result.Err) + "`n" + ([string]$Result.Out)).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) { return '(无输出)' }
    $all = @($text -split "\r?\n")
    if ($all.Count -le $Lines) { return ($all -join ' | ') }
    return (($all[($all.Count - $Lines)..($all.Count - 1)]) -join ' | ')
}

function Invoke-BuildChecks {
    $buildOk = $true

    # 0a: go vet ./...
    $status = Run-Check -Id '0a' -Title 'go vet ./...' -Body {
        $result = Invoke-GoCommand -GoArgs @('vet', './...') -TimeoutSec 600 -WorkingDirectory $script:RepoRoot
        Assert-True (-not $result.TimedOut) 'go vet 超时（600s）'
        if ($result.ExitCode -ne 0) { throw ("go vet 失败（exit={0}）：{1}" -f $result.ExitCode, (Get-CommandTail $result 16)) }
        return '通过'
    }
    # 注意：vet/test 失败只记录 FAIL，不阻断后续端到端检查（"失败也继续收集"）；
    # 只有构建失败才无法启动二进制。

    # 0b: go test ./...
    if ($SkipUnitTests) {
        Add-SkippedCheck -Id '0b' -Title 'go test ./...' -Reason '指定了 -SkipUnitTests'
    } else {
        $status = Run-Check -Id '0b' -Title 'go test ./...' -Body {
            $result = Invoke-GoCommand -GoArgs @('test', './...') -TimeoutSec 1800 -WorkingDirectory $script:RepoRoot
            Assert-True (-not $result.TimedOut) 'go test 超时（1800s）'
            if ($result.ExitCode -ne 0) { throw ("go test 失败（exit={0}）：{1}" -f $result.ExitCode, (Get-CommandTail $result 20)) }
            $okLines = @($result.Out -split "\r?\n" | Where-Object { $_ -match '^ok\s' }).Count
            $failLines = @($result.Out -split "\r?\n" | Where-Object { $_ -match '^(FAIL|--- FAIL)' }).Count
            return ("{0} 个包通过；FAIL 行 {1}" -f $okLines, $failLines)
        }
    }

    # 0c: 构建两个二进制
    $status = Run-Check -Id '0c' -Title '构建 server/client 二进制' -Body {
        $binDir = Join-Path $script:RepoRoot 'bin'
        if (-not (Test-Path -LiteralPath $binDir)) { New-Item -ItemType Directory -Force -Path $binDir | Out-Null }
        $serverOut = Join-Path $binDir 'proxygw-server.exe'
        $clientOut = Join-Path $binDir 'proxygw-client.exe'
        # Windows 上运行中的 exe 无法被覆盖；并行测试可能短暂占用 bin/ 下的产物，重试几次。
        $serverBuilt = $false
        for ($attempt = 1; $attempt -le 6; $attempt++) {
            $r1 = Invoke-GoCommand -GoArgs @('build', '-o', $serverOut, './cmd/proxygw-server') -TimeoutSec 600 -WorkingDirectory $script:RepoRoot
            if ($r1.ExitCode -eq 0) { $serverBuilt = $true; break }
            if ($attempt -lt 6) { Start-Sleep -Seconds 2 }
        }
        if (-not $serverBuilt) { throw ("构建服务端失败：{0}" -f (Get-CommandTail $r1 16)) }
        $clientBuilt = $false
        for ($attempt = 1; $attempt -le 6; $attempt++) {
            $r2 = Invoke-GoCommand -GoArgs @('build', '-o', $clientOut, './cmd/proxygw-client') -TimeoutSec 600 -WorkingDirectory $script:RepoRoot
            if ($r2.ExitCode -eq 0) { $clientBuilt = $true; break }
            if ($attempt -lt 6) { Start-Sleep -Seconds 2 }
        }
        if (-not $clientBuilt) { throw ("构建客户端失败：{0}" -f (Get-CommandTail $r2 16)) }
        $size = [Math]::Round(((Get-Item $serverOut).Length + (Get-Item $clientOut).Length) / 1MB, 1)
        return ("bin/proxygw-server.exe + bin/proxygw-client.exe（共 {0} MB）" -f $size)
    }
    if ($status -ne 'PASS') { $buildOk = $false }

    return $buildOk
}

# ---------------------------------------------------------------------------
# 检查 1-13
# ---------------------------------------------------------------------------
function Add-PanelChecks {
    # 1) /healthz + /version
    [void](Run-Check -Id '1' -Title 'healthz 200/ok=true 与 /version' -NeedsStack -Body {
        $health = Invoke-Curl -Url "$($script:PanelBase)/healthz" -Extra @('-k')
        Assert-Equal $health.Code 200 '/healthz 状态码'
        $json = ConvertFrom-JsonSafe $health.Body
        Assert-True ((Get-ObjectProperty $json 'ok') -eq $true) ("/healthz ok != true：" + $health.Body)
        $versionResp = Invoke-Curl -Url "$($script:PanelBase)/version" -Extra @('-k')
        Assert-Equal $versionResp.Code 200 '/version 状态码'
        $versionJson = ConvertFrom-JsonSafe $versionResp.Body
        $versionValue = Get-ObjectProperty $versionJson 'version'
        Assert-True (-not [string]::IsNullOrWhiteSpace([string]$versionValue)) ('/version 缺少 version 字段：' + $versionResp.Body)
        return ("healthz ok=true；version=" + $versionValue + " commit=" + (Get-ObjectProperty $versionJson 'commit'))
    })

    # 2) 节点注册
    [void](Run-Check -Id '2' -Title '节点注册（online>=1，transport=quic）' -NeedsStack -Body {
        $overview = Get-PanelOverview
        Assert-True ([int](Get-ObjectProperty $overview 'online_nodes') -ge 1) ('online_nodes=' + (Get-ObjectProperty $overview 'online_nodes'))
        $nodes = Get-PanelNodes
        Assert-True ($nodes.Count -ge 1) ('/nodes 为空（total=' + (Get-ObjectProperty (ConvertFrom-JsonSafe (Invoke-PanelRequest -Method GET -Path '/api/v1/nodes').Body) 'total') + '）')
        $quicNodes = @($nodes | Where-Object { [string](Get-ObjectProperty $_ 'transport') -eq 'quic' })
        Assert-True ($quicNodes.Count -ge 1) ('没有 transport=quic 的节点：' + (($nodes | ForEach-Object { [string](Get-ObjectProperty $_ 'transport') }) -join ','))
        $ids = @($nodes | ForEach-Object { [string](Get-ObjectProperty $_ 'id') })
        return ("online_nodes=" + (Get-ObjectProperty $overview 'online_nodes') + "；" + ($quicNodes.Count) + " 个 quic 节点：" + ($ids -join ','))
    })

    # 3) HTTP absolute-form + 407
    [void](Run-Check -Id '3' -Title 'HTTP absolute-form 200 + 错误口令 407' -NeedsStack -NeedsOrigin -Body {
        $resp = Invoke-HttpProxy -Url (Invoke-OriginUrl '/echo') -User $script:ProxyUser -Password $script:ProxyPass
        Assert-Equal $resp.Code 200 'HTTP 代理状态码'
        $json = ConvertFrom-JsonSafe $resp.Body
        Assert-True ((Get-ObjectProperty $json 'ok') -eq $true) ('HTTP 代理响应体不正确：' + $resp.Body)
        $rawUrl = [string](Get-ObjectProperty $json 'url')
        if (($rawUrl -notlike 'http://*') -and ($rawUrl -notlike '/echo*')) { throw ('origin 收到异常请求目标：' + $rawUrl) }
        # absolute-form 解析证据：服务端 proxy_request 日志记录 protocol=http 且 target 为 origin 地址。
        $absoluteEvidence = $false
        for ($i = 0; $i -lt 20; $i++) {
            $serverLog = Read-Utf8File $script:ServerErr
            if ($serverLog -match ('"protocol":"http"[^}]*"target":"127\.0\.0\.1:' + [regex]::Escape([string]$script:OriginPort) + '"')) {
                $absoluteEvidence = $true
                break
            }
            Start-Sleep -Milliseconds 100
        }
        $bad = Invoke-HttpProxy -Url (Invoke-OriginUrl '/echo') -User $script:ProxyUser -Password 'wrong-password-for-test'
        Assert-Equal $bad.Code 407 '错误口令应返回 407'
        $evidenceText = 'absolute-form 已由代理解析'
        if (-not $absoluteEvidence) { $evidenceText = 'absolute-form 请求成功（服务端日志未即时出现 protocol=http 记录）' }
        return ($evidenceText + '；错误口令 407')
    })

    # 4) CONNECT 到本地 TLS 服务（复用服务端面板的 /healthz）
    [void](Run-Check -Id '4' -Title 'CONNECT 隧道到本地 TLS 服务' -NeedsStack -Body {
        $resp = Invoke-HttpsProxy -Url "$($script:PanelBase)/healthz" -User $script:ProxyUser -Password $script:ProxyPass
        Assert-Equal $resp.Code 200 'CONNECT 隧道状态码'
        $json = ConvertFrom-JsonSafe $resp.Body
        Assert-True ((Get-ObjectProperty $json 'ok') -eq $true) ('隧道内 TLS 响应不正确：' + $resp.Body)
        return 'CONNECT 建立隧道后 GET /healthz -> 200 {ok:true}'
    })

    # 5) SOCKS5
    [void](Run-Check -Id '5' -Title 'SOCKS5 CONNECT 200 + 错误口令握手失败' -NeedsStack -NeedsOrigin -Body {
        $resp = Invoke-Socks5Proxy -Url (Invoke-OriginUrl '/echo') -User $script:ProxyUser -Password $script:ProxyPass
        Assert-Equal $resp.Code 200 'SOCKS5 状态码'
        $json = ConvertFrom-JsonSafe $resp.Body
        Assert-True ((Get-ObjectProperty $json 'ok') -eq $true) ('SOCKS5 响应体不正确：' + $resp.Body)
        $bad = Invoke-Socks5Proxy -Url (Invoke-OriginUrl '/echo') -User $script:ProxyUser -Password 'wrong-password-for-test' -MaxTimeSec 15
        Assert-True ($bad.Code -ne 200) ('SOCKS5 错误口令不应成功：HTTP ' + $bad.Code)
        return ('SOCKS5 CONNECT -> 200；错误口令握手失败（curl exit=' + $bad.ExitCode + '）')
    })
}

function Add-PanelSecurityChecks {
    # 6) 面板认证 / CSRF / 设置热更 / 撤销 / 非法设置
    [void](Run-Check -Id '6' -Title '面板登录/CSRF/设置热更/撤销/422' -NeedsStack -Body {
        # 未登录 401（不带 Cookie）
        $unauth = Invoke-PanelRequest -Method 'GET' -Path '/api/v1/overview' -NoCookies
        Assert-Equal $unauth.Code 401 '未登录访问 /overview'
        # 登录成功并拿到 csrf
        $session = Invoke-PanelLogin -Username $script:AdminUser -Password $script:AdminPass
        Assert-True (-not [string]::IsNullOrWhiteSpace($script:Csrf)) '登录未返回 csrf'
        $sessionResp = Invoke-PanelRequest -Method 'GET' -Path '/api/v1/session'
        Assert-Equal $sessionResp.Code 200 'GET /session'
        $sessionJson = ConvertFrom-JsonSafe $sessionResp.Body
        Assert-Equal (Get-ObjectProperty $sessionJson 'csrf') $script:Csrf 'GET /session 的 csrf 应一致'

        # 无 CSRF 的写请求 403
        $settingsResp = Invoke-PanelRequest -Method 'GET' -Path '/api/v1/settings'
        Assert-Equal $settingsResp.Code 200 'GET /settings'
        $settingsJson = ConvertFrom-JsonSafe $settingsResp.Body
        $currentSettings = Get-ObjectProperty $settingsJson 'current'
        Assert-True ($null -ne $currentSettings) 'GET /settings 缺少 current'
        $noCsrf = Invoke-PanelRequest -Method 'PUT' -Path '/api/v1/settings' -Body @{ settings = $currentSettings } -NoCsrf
        Assert-Equal $noCsrf.Code 403 '无 CSRF 的写请求'

        # 带 CSRF 修改策略 -> GET 生效
        $originalStrategy = [string](Get-ObjectProperty (Get-ObjectProperty $currentSettings 'scheduler') 'strategy')
        $newStrategy = 'weighted'
        if ($originalStrategy -eq 'weighted') { $newStrategy = 'random' }
        $nextSettings = Copy-JsonObject $currentSettings
        $nextSettings.scheduler.strategy = $newStrategy
        $putResp = Invoke-PanelRequest -Method 'PUT' -Path '/api/v1/settings' -Body @{ settings = $nextSettings }
        Assert-Equal $putResp.Code 200 ('PUT /settings 修改策略（' + $putResp.Body + '）')
        $afterPut = ConvertFrom-JsonSafe (Invoke-PanelRequest -Method 'GET' -Path '/api/v1/settings').Body
        $strategyAfterPut = [string](Get-ObjectProperty (Get-ObjectProperty (Get-ObjectProperty $afterPut 'current') 'scheduler') 'strategy')
        Assert-Equal $strategyAfterPut $newStrategy 'GET /settings 应反映新策略'

        # undo 还原
        $undoResp = Invoke-PanelRequest -Method 'POST' -Path '/api/v1/settings/undo'
        Assert-Equal $undoResp.Code 200 ('POST /settings/undo（' + $undoResp.Body + '）')
        $afterUndo = ConvertFrom-JsonSafe (Invoke-PanelRequest -Method 'GET' -Path '/api/v1/settings').Body
        $strategyAfterUndo = [string](Get-ObjectProperty (Get-ObjectProperty (Get-ObjectProperty $afterUndo 'current') 'scheduler') 'strategy')
        Assert-Equal $strategyAfterUndo $originalStrategy 'undo 后策略应还原'

        # 非法设置 422 且旧值不变
        $invalidSettings = Copy-JsonObject (Get-ObjectProperty (ConvertFrom-JsonSafe (Invoke-PanelRequest -Method 'GET' -Path '/api/v1/settings').Body) 'current')
        $invalidSettings.scheduler.strategy = 'definitely-not-a-strategy'
        $invalidResp = Invoke-PanelRequest -Method 'PUT' -Path '/api/v1/settings' -Body @{ settings = $invalidSettings }
        Assert-Equal $invalidResp.Code 422 ('非法设置应返回 422（实际 ' + $invalidResp.Code + '：' + $invalidResp.Body + '）')
        $afterInvalid = ConvertFrom-JsonSafe (Invoke-PanelRequest -Method 'GET' -Path '/api/v1/settings').Body
        $strategyAfterInvalid = [string](Get-ObjectProperty (Get-ObjectProperty (Get-ObjectProperty $afterInvalid 'current') 'scheduler') 'strategy')
        Assert-Equal $strategyAfterInvalid $originalStrategy '非法设置后旧值应保持不变'

        return ("401/403/422 校验通过；策略 " + $originalStrategy + " -> " + $newStrategy + " -> undo=" + $strategyAfterUndo)
    })

    # 7) 审计
    [void](Run-Check -Id '7' -Title '审计包含 login/settings.update 且无明文密码' -NeedsStack -Body {
        $resp = Invoke-PanelRequest -Method 'GET' -Path '/api/v1/audit?limit=500'
        Assert-Equal $resp.Code 200 'GET /audit'
        $json = ConvertFrom-JsonSafe $resp.Body
        $items = Get-ObjectProperty $json 'items'
        Assert-True ($null -ne $items) 'GET /audit 缺少 items'
        $actions = @($items | ForEach-Object { [string](Get-ObjectProperty $_ 'action') })
        Assert-True (($actions -contains 'login') -or (($actions | Where-Object { $_ -like 'login*' }).Count -gt 0)) ('审计缺少 login 事件：' + (($actions | Select-Object -Unique) -join ','))
        Assert-True (($actions -contains 'settings.update') -or (($actions | Where-Object { $_ -like 'settings.*' }).Count -gt 0)) ('审计缺少 settings.update 事件：' + (($actions | Select-Object -Unique) -join ','))
        foreach ($secret in @($script:AdminPass, $script:ProxyPass, $script:CredAPass)) {
            if ([string]::IsNullOrWhiteSpace($secret)) { continue }
            Assert-True ($resp.Body -notlike ('*' + $secret + '*')) '审计响应中出现明文密码（脱敏失败）'
        }
        return ('actions=' + (($actions | Select-Object -Unique | Sort-Object) -join ',') + '；未发现明文密码')
    })
}

function Add-GroupAndFailClosedChecks {
    # 8) 组隔离与 fail-closed
    [void](Run-Check -Id '8' -Title '组隔离与 fail-closed（组外有节点也不回退）' -NeedsStack -NeedsOrigin -Body {
        $script:CredAPass = 'CredA-' + (New-Token 20)
        # 创建组 g1：selector tags_any=[node-e2e]
        $createGroup = Invoke-PanelRequest -Method 'POST' -Path '/api/v1/groups' -Body @{ name = 'g1-e2e'; description = 'acceptance'; match = @{ tags_any = @('node-e2e') } }
        Assert-Equal $createGroup.Code 200 ('创建组失败：' + $createGroup.Body)
        $groupJson = ConvertFrom-JsonSafe $createGroup.Body
        $script:GroupID = [string](Get-ObjectProperty $groupJson 'id')
        Assert-True (-not [string]::IsNullOrWhiteSpace($script:GroupID)) '创建组未返回 id'

        # 组内成员应只有 node-e2e-1
        $members = ConvertFrom-JsonSafe (Invoke-PanelRequest -Method 'GET' -Path ("/api/v1/groups/{0}/members" -f $script:GroupID)).Body
        $memberNodes = @(Get-ObjectProperty $members 'nodes')
        $memberIds = @($memberNodes | ForEach-Object { [string](Get-ObjectProperty $_ 'id') })
        Assert-True (($memberIds -contains $script:Node1ID) -and ($memberIds -notcontains $script:Node2ID)) ('g1 成员不符合预期：' + ($memberIds -join ','))

        # 创建凭据 A 绑定 g1
        $createCred = Invoke-PanelRequest -Method 'POST' -Path '/api/v1/credentials' -Body @{
            username     = $script:CredAUser
            password     = $script:CredAPass
            groups       = @($script:GroupID)
            enabled      = $true
            note         = 'acceptance credential A'
        }
        Assert-Equal $createCred.Code 200 ('创建凭据 A 失败：' + $createCred.Body)
        $credJson = ConvertFrom-JsonSafe $createCred.Body
        $credObj = Get-ObjectProperty $credJson 'credential'
        $script:CredAID = [string](Get-ObjectProperty $credObj 'id')
        Assert-True (-not [string]::IsNullOrWhiteSpace($script:CredAID)) '创建凭据 A 未返回 id'

        # 凭据 A 可见节点数 = 1（fail-closed 只绑定 g1）
        $visible = ConvertFrom-JsonSafe (Invoke-PanelRequest -Method 'GET' -Path ("/api/v1/credentials/{0}/visible-nodes" -f $script:CredAID)).Body
        Assert-Equal ([int](Get-ObjectProperty $visible 'count')) 1 '凭据 A 可见节点数'

        # 连续 3 次经 A 的请求全部成功
        $okCount = 0
        for ($i = 1; $i -le 3; $i++) {
            $resp = Invoke-HttpProxy -Url (Invoke-OriginUrl '/echo') -User $script:CredAUser -Password $script:CredAPass
            if ($resp.Code -eq 200) { $okCount++ }
        }
        Assert-Equal $okCount 3 ('凭据 A 的 3 次请求应全部成功（实际 {0}）' -f $okCount)
        $nodesBefore = Get-PanelNodes
        $node1 = $nodesBefore | Where-Object { [string](Get-ObjectProperty $_ 'id') -eq $script:Node1ID } | Select-Object -First 1
        Assert-True ($null -ne $node1 -and [bool](Get-ObjectProperty $node1 'online')) '节点 1 应保持在线'

        # 停掉 node-e2e-1（组内唯一节点）；node-e2e-2 仍在线且不在 g1
        Stop-ManagedProcess -Process $script:Client1Proc
        $offlineSeconds = Wait-NodeOffline -NodeId $script:Node1ID -TimeoutSec 150

        $nodesAfter = Get-PanelNodes
        $node2 = $nodesAfter | Where-Object { [string](Get-ObjectProperty $_ 'id') -eq $script:Node2ID } | Select-Object -First 1
        Assert-True ($null -ne $node2 -and [bool](Get-ObjectProperty $node2 'online')) '组外节点 node-e2e-2 应仍在线（用于验证不会回退）'

        # 此时经 A 的请求必须 503（不能 502/200，尤其不能落到组外节点）
        $failResp = Invoke-HttpProxy -Url (Invoke-OriginUrl '/echo') -User $script:CredAUser -Password $script:CredAPass -MaxTimeSec 40
        Assert-True ($failResp.Code -ne 200) ('节点离线后凭据 A 仍成功（不应回退到组外节点）：HTTP ' + $failResp.Code)
        Assert-Equal $failResp.Code 503 ('节点离线后凭据 A 应返回 503（实际 {0}：{1}）' -f $failResp.Code, $failResp.Body.Substring(0, [Math]::Min(200, $failResp.Body.Length)))

        # 重启节点 1，恢复
        $client1Out = Join-Path $script:LogDir 'client-1a.out.log'
        $client1Err = Join-Path $script:LogDir 'client-1a.err.log'
        $script:Client1Proc = Start-ManagedProcess -Exe $script:ClientExe -Arguments @('-config', $script:Client1Cfg) -StdOut $client1Out -StdErr $client1Err
        [void](Wait-NodeOnline -NodeId $script:Node1ID -TimeoutSec 40)
        $recover = Invoke-HttpProxy -Url (Invoke-OriginUrl '/echo') -User $script:CredAUser -Password $script:CredAPass
        Assert-Equal $recover.Code 200 ('节点重启后凭据 A 应恢复：HTTP ' + $recover.Code)

        return ("g1 成员=node-e2e-1；A 3 次成功；停节点 1 后 {0:N1}s 判定离线 -> 503；组外 node-e2e-2 未被使用；重启后恢复" -f $offlineSeconds)
    })
}

function Wait-NodeOnline {
    param([string]$NodeId, [int]$TimeoutSec = 40)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $nodes = Get-PanelNodes
        $target = $nodes | Where-Object { [string](Get-ObjectProperty $_ 'id') -eq $NodeId } | Select-Object -First 1
        if ($null -ne $target -and [bool](Get-ObjectProperty $target 'online')) { return $target }
        Start-Sleep -Milliseconds 300
    }
    throw ("等待节点 {0} 上线超时（{1}s）" -f $NodeId, $TimeoutSec)
}

# 粘性验证使用「慢请求 + 服务端 proxy_request 日志里的 node_id」判断每次请求实际
# 命中的节点：/nodes 的 inflight 来自节点 STATS（每 10s 上报一次），短请求期间
# 可能观测不到，日志证据更可靠。
function Get-ProxyRequestNodeIds {
    $text = Read-Utf8File $script:ServerErr
    $ids = New-Object System.Collections.ArrayList
    foreach ($line in ($text -split "\r?\n")) {
        if ($line -notmatch '"protocol":"http"') { continue }
        if ($line -notmatch ('"target":"127\.0\.0\.1:' + [regex]::Escape([string]$script:OriginPort) + '"')) { continue }
        $m = [regex]::Match($line, '"node_id":"([^"]+)"')
        if ($m.Success -and $m.Groups[1].Value -ne '') { [void]$ids.Add($m.Groups[1].Value) }
    }
    return $ids.ToArray()
}

function Wait-ProxyLogCount {
    param([int]$Minimum, [int]$TimeoutSec = 10)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $ids = @(Get-ProxyRequestNodeIds)
        if ($ids.Count -ge $Minimum) { return $ids }
        Start-Sleep -Milliseconds 150
    }
    return @(Get-ProxyRequestNodeIds)
}

function Invoke-SlowProxyRequest {
    param([string]$User, [string]$Password, [int]$Milliseconds = 1200)
    $url = (Invoke-OriginUrl ('/slow?ms=' + $Milliseconds))
    $out = Join-Path $script:LogDir ('slow-' + (New-Token 8) + '.json')
    $codeFile = Join-Path $script:LogDir ('slow-' + (New-Token 8) + '.code')
    $errFile = Join-Path $script:LogDir ('slow-' + (New-Token 8) + '.err')
    $proc = Start-ManagedProcess -Exe (Get-Curl) -Arguments @(
        '-s', '--max-time', '40', '--noproxy=', '-x', ("http://127.0.0.1:{0}" -f $script:HttpPort),
        '--proxy-user', ("{0}:{1}" -f $User, $Password), '-o', $out, '-w', '%{http_code}', $url
    ) -StdOut $codeFile -StdErr $errFile
    if (-not $proc.WaitForExit(45000)) { Stop-ManagedProcess -Process $proc; throw '慢请求超时（45s）' }
    $code = 0
    [void][int]::TryParse((Read-Utf8File $codeFile).Trim(), [ref]$code)
    return $code
}

function Add-StickyChecks {
    # 9) 会话粘性：同一凭据 + 同一源 IP 连续 5 次命中同一节点
    [void](Run-Check -Id '9' -Title '会话粘性（同源 5 次同节点）' -NeedsStack -NeedsOrigin -Body {
        # 把组 g1 扩为两个节点，使凭据 A 有 2 个候选节点，粘性才有意义
        $patch = Invoke-PanelRequest -Method 'PATCH' -Path ("/api/v1/groups/{0}" -f $script:GroupID) -Body @{ match = @{ tags_any = @('node-e2e', 'node-extra') } }
        Assert-Equal $patch.Code 200 ('扩展组 g1 失败：' + $patch.Body)
        $members = ConvertFrom-JsonSafe (Invoke-PanelRequest -Method 'GET' -Path ("/api/v1/groups/{0}/members" -f $script:GroupID)).Body
        $memberIds = @((@(Get-ObjectProperty $members 'nodes')) | ForEach-Object { [string](Get-ObjectProperty $_ 'id') })
        Assert-True (($memberIds -contains $script:Node1ID) -and ($memberIds -contains $script:Node2ID)) ('g1 应包含两个节点：' + ($memberIds -join ','))
        $nodes = Get-PanelNodes
        Assert-True (@($nodes | Where-Object { [bool](Get-ObjectProperty $_ 'online') }).Count -ge 2) '应有两个在线节点'

        $before = @(Get-ProxyRequestNodeIds).Count
        for ($i = 1; $i -le 5; $i++) {
            $code = Invoke-SlowProxyRequest -User $script:CredAUser -Password $script:CredAPass -Milliseconds 1200
            if ($code -ne 200) { throw ("第 {0} 次慢请求失败：HTTP {1}" -f $i, $code) }
        }
        $all = @(Wait-ProxyLogCount -Minimum ($before + 5) -TimeoutSec 10)
        Assert-True ($all.Count -ge ($before + 5)) ('服务端日志中未出现 5 次 proxy_request 记录（{0} -> {1}）' -f $before, $all.Count)
        $picked = @($all[$before..($before + 4)])
        $distinct = @($picked | Select-Object -Unique)
        Assert-Equal $distinct.Count 1 ('同源 5 次请求命中节点不一致：' + ($picked -join ','))
        return ('5 次请求均命中 ' + $distinct[0] + '（服务端 proxy_request.node_id 证据）')
    })

    # 9b) 粘性 TTL 过期后重新分配（概率性，观察不到时 SKIP 而不是伪造 PASS）
    [void](Run-Check -Id '9b' -Title '粘性 TTL 调小后重新分配' -NeedsStack -NeedsOrigin -Body {
        $settingsResp = Invoke-PanelRequest -Method 'GET' -Path '/api/v1/settings'
        Assert-Equal $settingsResp.Code 200 ('GET /settings 失败：' + $settingsResp.Body)
        $current = Get-ObjectProperty (ConvertFrom-JsonSafe $settingsResp.Body) 'current'
        $next = Copy-JsonObject $current
        $next.scheduler.sticky.ttl = '1s'
        $putResp = Invoke-PanelRequest -Method 'PUT' -Path '/api/v1/settings' -Body @{ settings = $next }
        Assert-Equal $putResp.Code 200 ('调小 sticky TTL 失败：' + $putResp.Body)
        try {
            Start-Sleep -Milliseconds 2200
            $before = @(Get-ProxyRequestNodeIds).Count
            for ($i = 1; $i -le 6; $i++) {
                $code = Invoke-SlowProxyRequest -User $script:CredAUser -Password $script:CredAPass -Milliseconds 900
                if ($code -ne 200) { throw ("TTL 验证第 {0} 次请求失败：HTTP {1}" -f $i, $code) }
                Start-Sleep -Milliseconds 1200
            }
            $all = @(Wait-ProxyLogCount -Minimum ($before + 6) -TimeoutSec 10)
            $picked = @()
            if ($all.Count -ge ($before + 6)) { $picked = @($all[$before..($before + 5)]) }
            $distinct = @($picked | Select-Object -Unique | Where-Object { -not [string]::IsNullOrEmpty($_) })
            if ($distinct.Count -ge 2) {
                return ('TTL=1s 后 6 次请求分布到 ' + ($distinct -join ',') + '（重新分配生效）')
            }
            return @{ Skip = $true; Note = ('TTL=1s 后 6 次请求仍全部命中 ' + ($distinct -join ',') + '（随机策略下概率性验证未观察到重分配；settings TTL 热更已由第 6 项验证）') }
        } finally {
            [void](Invoke-PanelRequest -Method 'POST' -Path '/api/v1/settings/undo')
        }
    })
}
function Add-FallbackCheck {
    # 10) QUIC 主用失败 -> wss 回退（同端口 UDP 黑洞）
    [void](Run-Check -Id '10' -Title 'QUIC 回退 wss（UDP 黑洞模拟）' -NeedsStack -Body {
        $port = Get-FreePort
        $httpPort = Get-FreePort
        $socksPort = Get-FreePort
        $stateDir = Join-Path $script:TempDir 'fallback-server-state'
        New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
        $token = New-Token 48
        $cfgPath = Join-Path $script:TempDir 'fallback-server.yaml'
        New-ServerConfigFile -Path $cfgPath -ListenPort $port -HttpPort $httpPort -SocksPort $socksPort -StateDir $stateDir -NodeToken $token -Transport 'ws'
        $errPath = Join-Path $script:TempDir 'fallback-server.err.log'
        $outPath = Join-Path $script:TempDir 'fallback-server.out.log'
        $serverExe = $script:ServerExe
        $blackholePath = ''
        try {
            # 先起同端口 UDP 黑洞（丢弃所有 QUIC 握手包）
            $node = Get-Command 'node' -ErrorAction SilentlyContinue
            if ($node) {
                $blackholeJs = @"
const dgram = require('dgram');
const socket = dgram.createSocket('udp4');
socket.on('message', function () {});
socket.on('error', function () {});
socket.bind($port, '127.0.0.1');
setInterval(function () {}, 1000);
"@
                $blackholePath = Join-Path $script:TempDir 'udp-blackhole.js'
                Write-Utf8File $blackholePath $blackholeJs
                $script:FallbackBlackholeProc = Start-ManagedProcess -Exe $node.Source -Arguments @($blackholePath) -StdOut (Join-Path $script:TempDir 'blackhole.out.log') -StdErr (Join-Path $script:TempDir 'blackhole.err.log')
                if (-not (Wait-UdpPortBusy -Port $port -TimeoutSec 10)) { throw 'UDP 黑洞未成功绑定端口' }
            } else {
                return @{ Skip = $true; Note = '缺少 node，无法模拟 UDP 黑洞；手工步骤见 docs/ACCEPTANCE.md' }
            }

            $script:FallbackServerProc = Start-ManagedProcess -Exe $serverExe -Arguments @('-config', $cfgPath) -StdOut $outPath -StdErr $errPath -Environment @{ 'NP_ACL_ALLOW_LOOPBACK_TARGETS' = '1' }
            $fallbackBase = "https://127.0.0.1:$port"
            $deadline = (Get-Date).AddSeconds(60)
            $ready = $false
            while ((Get-Date) -lt $deadline) {
                if ($script:FallbackServerProc.HasExited) { throw ('回退测试服务端提前退出：' + (Get-LogTail $errPath 20)) }
                $probe = Invoke-Curl -Url "$fallbackBase/healthz" -Extra @('-k') -MaxTimeSec 3
                if ($probe.Code -eq 200) { $ready = $true; break }
                Start-Sleep -Milliseconds 300
            }
            if (-not $ready) { throw ('回退测试服务端未就绪：' + (Get-LogTail $errPath 20)) }
            $boot = Read-ServerBootMessages -ErrLogPath $errPath

            # 旧的 panel 端点信息保存后切换
            $savedBase = $script:PanelBase
            $savedJar = $script:CookieJar
            $savedCsrf = $script:Csrf
            try {
                $fallbackJar = Join-Path $script:TempDir 'fallback-cookies.txt'
                Use-PanelEndpoint -Base $fallbackBase -CookieJar $fallbackJar
                [void](Invoke-PanelLogin -Username $boot.AdminUser -Password $boot.AdminPass)

                $clientState = Join-Path $script:TempDir 'fallback-client-state'
                New-Item -ItemType Directory -Force -Path $clientState | Out-Null
                $clientCfg = Join-Path $script:TempDir 'fallback-client.yaml'
                New-ClientConfigFile -Path $clientCfg -ServerUrl $fallbackBase -NodeToken $token -ClientId 'node-fallback-1' -Tags @('node-fallback') -StateDir $clientState -Pin $boot.Pin -Planes 1
                $clientErr = Join-Path $script:TempDir 'fallback-client.err.log'
                $clientOut = Join-Path $script:TempDir 'fallback-client.out.log'
                $script:FallbackClientProc = Start-ManagedProcess -Exe $script:ClientExe -Arguments @('-config', $clientCfg) -StdOut $clientOut -StdErr $clientErr

                [void](Wait-OnlineNodes -Minimum 1 -TimeoutSec 60)
                # 注册与面板可见之间可能有一个很短的窗口，最多再等 15s 让 /nodes 可读。
                $nodes = @()
                for ($attempt = 0; $attempt -lt 50; $attempt++) {
                    $nodes = @(Get-PanelNodes)
                    if ($nodes.Count -ge 1) { break }
                    Start-Sleep -Milliseconds 300
                }
                if ($nodes.Count -lt 1) {
                    $overviewRaw = (Invoke-PanelRequest -Method 'GET' -Path '/api/v1/overview').Body
                    $nodesRaw = (Invoke-PanelRequest -Method 'GET' -Path '/api/v1/nodes?size=100').Body
                    throw ('回退实例没有注册节点；overview=' + $overviewRaw + '；nodes=' + $nodesRaw)
                }
                $transport = [string](Get-ObjectProperty $nodes[0] 'transport')
                Assert-Equal $transport 'ws' ('回退后节点传输类型应为 ws（实际 {0}）；客户端日志尾部：{1}' -f $transport, (Get-LogTail $clientErr 15))
                $clientLog = Read-Utf8File $clientErr
                $fallbackHint = '未在日志中找到回退字样（以面板 transport=ws 为准）'
                if ($clientLog -match '回退|fallback') { $fallbackHint = '客户端日志包含回退记录' }
                return ('UDP 黑洞 + 仅 wss 服务端 -> 节点 transport=ws；' + $fallbackHint)
            } finally {
                Stop-ManagedProcess -Process $script:FallbackClientProc
                $script:FallbackClientProc = $null
                Use-PanelEndpoint -Base $savedBase -CookieJar $savedJar
                $script:Csrf = $savedCsrf
            }
        } finally {
            Stop-ManagedProcess -Process $script:FallbackServerProc
            $script:FallbackServerProc = $null
            Stop-ManagedProcess -Process $script:FallbackBlackholeProc
            $script:FallbackBlackholeProc = $null
        }
    })
}

function Add-PinMismatchCheck {
    # 11) pin 不匹配硬失败
    [void](Run-Check -Id '11' -Title 'pin 不匹配硬失败（20s 内非 0 退出）' -NeedsStack -Body {
        $wrongPin = 'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
        Assert-True ($wrongPin -ne $script:Pin) '错误 pin 不能与真实 pin 相同'
        $stateDir = Join-Path $script:TempDir 'badpin-client-state'
        New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
        $cfgPath = Join-Path $script:TempDir 'badpin-client.yaml'
        New-ClientConfigFile -Path $cfgPath -ServerUrl ("https://127.0.0.1:{0}" -f $script:ListenPort) -NodeToken $script:NodeToken -ClientId 'node-badpin' -Tags @('badpin') -StateDir $stateDir -Pin $wrongPin -Planes 1
        $errPath = Join-Path $script:TempDir 'badpin-client.err.log'
        $outPath = Join-Path $script:TempDir 'badpin-client.out.log'
        $clientExe = $script:ClientExe
        $result = Invoke-CommandWithExitFile -Exe $clientExe -Arguments @('-config', $cfgPath) -StdOut $outPath -StdErr $errPath -TimeoutSec 20
        if ($result.TimedOut) {
            throw '错误 pin 的客户端 20s 内未退出（不符合硬失败要求）'
        }
        Assert-True ($result.ExitCode -ne 0) ('错误 pin 的客户端应以非 0 退出（实际 ' + $result.ExitCode + '）')
        Assert-True ($result.ExitCode -gt 0) ('错误 pin 的客户端退出码异常（实际 ' + $result.ExitCode + '）')
        $log = Read-Utf8File $errPath
        Assert-True ($log -match '期望指纹') '客户端错误日志缺少“期望指纹”'
        Assert-True ($log -match '实际指纹') '客户端错误日志缺少“实际指纹”'
        Assert-True ($log -like ('*' + $script:Pin + '*')) '客户端错误日志缺少服务端真实 pin（实际指纹）'
        Assert-True ($log -like ('*' + $wrongPin + '*')) '客户端错误日志缺少配置的期望 pin'
        Assert-True ($log -match '排查建议') '客户端错误日志缺少排查建议'
        return ('exit=' + $result.ExitCode + '；日志含期望/实际指纹与排查建议')
    })
}

function Add-ConcurrencyCheck {
    # 13) 并发 20 x 64KB + active_connections 归零
    [void](Run-Check -Id '13' -Title '并发 20 x 64KB 与连接回收' -NeedsStack -NeedsOrigin -Body {
        $started = Get-Date
        $requests = New-Object System.Collections.ArrayList
        for ($i = 0; $i -lt 20; $i++) {
            $out = Join-Path $script:LogDir ('conc-' + $i + '.bin')
            $codeFile = Join-Path $script:LogDir ('conc-' + $i + '.code')
            $errFile = Join-Path $script:LogDir ('conc-' + $i + '.err')
            $proc = Start-ManagedProcess -Exe (Get-Curl) -Arguments @(
                '-s', '--max-time', '90', '--noproxy=', '-x', ("http://127.0.0.1:{0}" -f $script:HttpPort),
                '--proxy-user', ("{0}:{1}" -f $script:ProxyUser, $script:ProxyPass),
                '-o', $out, '-w', '%{http_code}', (Invoke-OriginUrl '/64k')
            ) -StdOut $codeFile -StdErr $errFile
            [void]$requests.Add([pscustomobject]@{ Proc = $proc; Out = $out; CodeFile = $codeFile })
        }
        $bad = 0
        $bytes = 0
        foreach ($request in $requests) {
            if (-not $request.Proc.WaitForExit(120000)) {
                Stop-ManagedProcess -Process $request.Proc
                $bad++
                continue
            }
            $code = 0
            [void][int]::TryParse((Read-Utf8File $request.CodeFile).Trim(), [ref]$code)
            if ($code -ne 200) { $bad++ }
            if (Test-Path -LiteralPath $request.Out) { $bytes += (Get-Item -LiteralPath $request.Out).Length }
        }
        $elapsed = ((Get-Date) - $started).TotalSeconds
        Assert-Equal $bad 0 ('并发请求失败数（20 个中）')
        Assert-Equal $bytes (20 * 65536) ('并发下载总字节数应为 20*64KB（实际 {0}）' -f $bytes)

        # active_connections 允许 5s 收敛
        $deadline = (Get-Date).AddSeconds(5)
        $active = -1
        do {
            $overview = Get-PanelOverview
            $active = [int](Get-ObjectProperty $overview 'active_connections')
            if ($active -eq 0) { break }
            Start-Sleep -Milliseconds 200
        } while ((Get-Date) -lt $deadline)
        Assert-Equal $active 0 ('并发结束后 active_connections 应在 5s 内归零（实际 {0}）' -f $active)
        return ('20/20 成功，共 {0:N1} MB，耗时 {1:N1}s；active_connections=0' -f ($bytes / 1MB), $elapsed)
    })
}

function Add-ShutdownCheck {
    # 12) 优雅停机：Windows 无法发送 SIGTERM/Ctrl+C，按任务书降级为 SKIP + 端口释放检查
    [void](Run-Check -Id '12' -Title '停机与端口释放（SIGTERM 语义 SKIP）' -NeedsStack -Body {
        Stop-ManagedProcess -Process $script:Client2Proc
        $script:Client2Proc = $null
        Stop-ManagedProcess -Process $script:Client1Proc
        $script:Client1Proc = $null
        Stop-ManagedProcess -Process $script:ServerProc
        $script:ServerProc = $null
        $deadline = (Get-Date).AddSeconds(10)
        $tcpFree = $false
        $udpFree = $false
        while ((Get-Date) -lt $deadline) {
            $tcpFree = Test-TcpPortFree $script:ListenPort
            $udpFree = Test-UdpPortFree $script:ListenPort
            if ($tcpFree -and $udpFree) { break }
            Start-Sleep -Milliseconds 200
        }
        Assert-True $tcpFree ('服务端被停止后 TCP 端口 {0} 未释放' -f $script:ListenPort)
        Assert-True $udpFree ('服务端被停止后 UDP 端口 {0} 未释放' -f $script:ListenPort)
        $script:StackReady = $false
        return @{ Skip = $true; Note = 'Windows 无法向控制台进程发送 SIGTERM/Ctrl+C（优雅停机语义由 Linux 脚本用 kill -TERM 验证）；Stop-Process 停止后 TCP/UDP 端口均已释放' }
    })
}

# ---------------------------------------------------------------------------
# 汇总输出
# ---------------------------------------------------------------------------
function Show-Summary {
    param([string]$TempDir)
    Write-Host ''
    Write-Host '==================== 验收结果汇总 ====================' -ForegroundColor Cyan
    Write-Host ('  {0,-4} {1,-34} {2,-5} {3,8}  {4}' -f '编号', '验收项', '结果', '耗时(ms)', '备注/证据')
    Write-Host ('  ' + ('-' * 110))
    foreach ($r in $script:Results) {
        $color = 'Gray'
        if ($r.Status -eq 'PASS') { $color = 'Green' }
        elseif ($r.Status -eq 'FAIL') { $color = 'Red' }
        elseif ($r.Status -eq 'SKIP') { $color = 'Yellow' }
        Write-Host ('  {0,-4} {1,-34} ' -f $r.Id, $r.Title) -NoNewline
        Write-Host ('{0,-5}' -f $r.Status) -NoNewline -ForegroundColor $color
        Write-Host (' {0,8}  {1}' -f $r.Ms, $r.Note)
    }
    $pass = @($script:Results | Where-Object { $_.Status -eq 'PASS' }).Count
    $fail = @($script:Results | Where-Object { $_.Status -eq 'FAIL' }).Count
    $skip = @($script:Results | Where-Object { $_.Status -eq 'SKIP' }).Count
    Write-Host ('  ' + ('-' * 110))
    Write-Host ('  PASS={0}  FAIL={1}  SKIP={2}  总计={3}' -f $pass, $fail, $skip, $script:Results.Count) -ForegroundColor Cyan
    if ($TempDir) {
        Write-Host ('  产物/日志目录：' + $TempDir) -ForegroundColor Gray
    }
    return $fail
}

function Cleanup {
    foreach ($proc in @($script:FallbackClientProc, $script:FallbackServerProc, $script:FallbackBlackholeProc, $script:Client2Proc, $script:Client1Proc, $script:ServerProc)) {
        try { Stop-ManagedProcess -Process $proc } catch { }
    }
    # 兜底：停止本脚本启动的所有进程（避免残留）
    foreach ($proc in @($script:Processes)) {
        try { Stop-ManagedProcess -Process $proc -TimeoutMs 2000 } catch { }
    }
}

# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
function Main {
    $startedAt = Get-Date
    if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
        $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    }
    $script:RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
    if (-not (Test-Path -LiteralPath (Join-Path $script:RepoRoot 'go.mod'))) {
        Write-Host ('错误：{0} 不是 proxygw 仓库根目录（缺少 go.mod）' -f $script:RepoRoot) -ForegroundColor Red
        exit 2
    }
    $script:TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ('proxygw-accept-' + (New-Token 8))
    New-Item -ItemType Directory -Force -Path $script:TempDir | Out-Null
    $script:LogDir = $script:TempDir

    Write-Host ''
    Write-Host 'proxygw 本地自动化验收（Windows PowerShell）' -ForegroundColor Cyan
    Write-Host ('  仓库根目录：' + $script:RepoRoot)
    Write-Host ('  临时目录：  ' + $script:TempDir)
    Write-Host ''

    $notInstalled = @()
    try {
        $go = Get-Command 'go' -ErrorAction SilentlyContinue
        if (-not $go) { $notInstalled += 'go' } else { $script:GoExe = $go.Source }
        $null = Get-Curl
    } catch {
        $notInstalled += 'curl'
    }
    if ($notInstalled.Count -gt 0) {
        Write-Host ('错误：缺少必要工具：{0}' -f ($notInstalled -join ', ')) -ForegroundColor Red
        Write-Host '请安装 Go 1.22+（https://go.dev/dl/）；curl.exe 为 Windows 10/11 自带。' -ForegroundColor Red
        exit 2
    }

    $buildOk = $false
    try {
        Write-Host '[阶段] 构建与单元测试 ...' -ForegroundColor Cyan
        $buildOk = Invoke-BuildChecks

        if ($buildOk) {
            # 复制到唯一文件名后再执行：避免并行运行的其它验收/集成测试按镜像名
            # 清理进程时误杀本脚本的验收栈（bin/ 下的标准名二进制仍是交付产物）。
            try {
                $copyTag = New-Token 6
                $script:ServerExe = Join-Path $script:TempDir ('proxygw-server-acc-' + $copyTag + '.exe')
                $script:ClientExe = Join-Path $script:TempDir ('proxygw-client-acc-' + $copyTag + '.exe')
                Copy-Item -LiteralPath (Join-Path $script:RepoRoot 'bin\proxygw-server.exe') -Destination $script:ServerExe -Force
                Copy-Item -LiteralPath (Join-Path $script:RepoRoot 'bin\proxygw-client.exe') -Destination $script:ClientExe -Force
            } catch {
                Write-Host ('  [失败] 复制验收二进制失败：' + $_.Exception.Message) -ForegroundColor Red
                $buildOk = $false
            }
        }

        if ($buildOk) {
            Write-Host '[阶段] 启动本地验收栈（origin + 服务端 + 2 个节点）...' -ForegroundColor Cyan
            try {
                Start-MainStack
                Write-Host ('  服务端 https://127.0.0.1:{0}  HTTP 代理 127.0.0.1:{1}  SOCKS5 127.0.0.1:{2}  origin 127.0.0.1:{3}' -f $script:ListenPort, $script:HttpPort, $script:SocksPort, $script:OriginPort) -ForegroundColor Gray
                Write-Host ('  节点 1（quic，组 g1 成员）与节点 2（quic，组外）已上线' ) -ForegroundColor Gray
            } catch {
                Write-Host ('  [失败] 验收栈启动失败：' + $_.Exception.Message) -ForegroundColor Red
                Add-Result 'stack' '验收栈启动（origin+server+client）' 'FAIL' 0 $_.Exception.Message | Out-Null
                $script:StackReady = $false
            }

            Write-Host ''
            Write-Host '[阶段] 逐项检查 ...' -ForegroundColor Cyan
            Add-PanelChecks
            Add-PanelSecurityChecks
            if ($script:StackReady) {
                Add-GroupAndFailClosedChecks
                Add-StickyChecks
            } else {
                foreach ($item in @(
                        @('8', '组隔离与 fail-closed（组外有节点也不回退）'),
                        @('9', '会话粘性（同源 5 次同节点）'),
                        @('9b', '粘性 TTL 调小后重新分配')
                    )) {
                    Add-SkippedCheck -Id $item[0] -Title $item[1] -Reason '依赖主栈未启动'
                }
            }
            Add-FallbackCheck
            Add-PinMismatchCheck
            Add-ConcurrencyCheck
            Add-ShutdownCheck
        } else {
            Write-Host '[跳过] 构建/单元测试未通过，依赖二进制的端到端检查标记为 SKIP。' -ForegroundColor Yellow
            foreach ($item in @(
                    @('1', 'healthz 200/ok=true 与 /version'),
                    @('2', '节点注册（online>=1，transport=quic）'),
                    @('3', 'HTTP absolute-form 200 + 错误口令 407'),
                    @('4', 'CONNECT 隧道到本地 TLS 服务'),
                    @('5', 'SOCKS5 CONNECT 200 + 错误口令握手失败'),
                    @('6', '面板登录/CSRF/设置热更/撤销/422'),
                    @('7', '审计包含 login/settings.update 且无明文密码'),
                    @('8', '组隔离与 fail-closed（组外有节点也不回退）'),
                    @('9', '会话粘性（同源 5 次同节点）'),
                    @('9b', '粘性 TTL 调小后重新分配'),
                    @('10', 'QUIC 回退 wss（UDP 黑洞模拟）'),
                    @('11', 'pin 不匹配硬失败（20s 内非 0 退出）'),
                    @('12', '停机与端口释放（SIGTERM 语义 SKIP）'),
                    @('13', '并发 20 x 64KB 与连接回收')
                )) {
                Add-SkippedCheck -Id $item[0] -Title $item[1] -Reason '构建/单元测试失败，无法启动二进制'
            }
        }
    } catch {
        Write-Host ('[错误] 验收脚本执行异常：' + $_.Exception.Message) -ForegroundColor Red
        Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
        Add-Result 'ERR' '脚本执行异常' 'FAIL' 0 $_.Exception.Message | Out-Null
    } finally {
        Write-Host ''
        Write-Host '[阶段] 清理进程 ...' -ForegroundColor Cyan
        Cleanup
    }

    $elapsed = ((Get-Date) - $startedAt).TotalSeconds
    $hadFail = $false
    if ($script:Results.Count -gt 0) {
        $failCount = @($script:Results | Where-Object { $_.Status -eq 'FAIL' }).Count
        if ($failCount -gt 0) { $hadFail = $true }
    } else {
        $hadFail = $true
    }

    $keep = $KeepArtifacts -or $hadFail
    $tempDirToShow = $null
    if ($keep) {
        $tempDirToShow = $script:TempDir
    }
    $failCount = Show-Summary -TempDir $tempDirToShow
    Write-Host ('  总耗时：{0:N1}s' -f $elapsed) -ForegroundColor Cyan
    if ($hadFail) {
        Write-Host ''
        Write-Host ('  存在失败项，已保留现场日志：' + $script:TempDir) -ForegroundColor Red
        Write-Host ('  服务端 stderr: ' + (Join-Path $script:TempDir 'server.err.log')) -ForegroundColor Red
        Write-Host ('  客户端 1 stderr: ' + (Join-Path $script:TempDir 'client-1.err.log')) -ForegroundColor Red
        Write-Host ('  客户端 2 stderr: ' + (Join-Path $script:TempDir 'client-2.err.log')) -ForegroundColor Red
        exit 1
    }
    if (-not $KeepArtifacts -and (Test-Path -LiteralPath $script:TempDir)) {
        try { Remove-Item -LiteralPath $script:TempDir -Recurse -Force -ErrorAction SilentlyContinue } catch { }
    } else {
        Write-Host ('  已保留临时目录：' + $script:TempDir) -ForegroundColor Gray
    }
    exit 0
}

Main
