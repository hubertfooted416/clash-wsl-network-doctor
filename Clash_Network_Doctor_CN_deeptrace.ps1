#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$ProxyHost = "127.0.0.1",
    [int]$ProxyPort = 7890,
    [int]$MixedPort = 7891,
    [int]$ApiPort   = 9090,
    [string]$ClashSecret = "",
    [string]$ReportRoot = "",
    [string]$SecretStorePath = "",
    [switch]$NoSecretPrompt = $false,
    [switch]$ForgetSavedSecret = $false
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

try {
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::UTF8
    $OutputEncoding = [System.Text.UTF8Encoding]::UTF8
} catch {}

$script:Summary = [ordered]@{}
$script:Diagnosis = New-Object System.Collections.Generic.List[string]
$script:Suggestions = New-Object System.Collections.Generic.List[string]
$script:Details = New-Object System.Collections.Generic.List[string]
$script:SecretLoadError = "<empty>"
$script:SecretSaveError = "<empty>"

function Add-Summary {
    param([string]$Name,[string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { $Value = "UNKNOWN" }
    $script:Summary[$Name] = $Value
}
function Add-Diagnosis {
    param([string]$Text)
    if ($Text -and -not $script:Diagnosis.Contains($Text)) { [void]$script:Diagnosis.Add($Text) }
}
function Add-Suggestion {
    param([string]$Text)
    if ($Text -and -not $script:Suggestions.Contains($Text)) { [void]$script:Suggestions.Add($Text) }
}
function Add-Detail {
    param([string]$Text)
    if ($Text -ne $null) { [void]$script:Details.Add($Text) }
}
function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 68) -ForegroundColor DarkCyan
    Write-Host (" {0}" -f $Title) -ForegroundColor Cyan
    Write-Host ("=" * 68) -ForegroundColor DarkCyan
}
function Write-KeyValue {
    param([string]$Key,[string]$Value,[ConsoleColor]$Color = [ConsoleColor]::Gray)
    Write-Host ("{0,-30}: " -f $Key) -NoNewline -ForegroundColor DarkGray
    Write-Host $Value -ForegroundColor $Color
}
function Write-StatusLine {
    param([string]$Label,[bool]$Ok,[string]$Detail = "")
    $mark = if ($Ok) { "[√]" } else { "[×]" }
    $color = if ($Ok) { "Green" } else { "Red" }
    Write-Host ("{0} {1}" -f $mark, $Label) -ForegroundColor $color
    if ($Detail) { Write-Host ("    {0}" -f $Detail) -ForegroundColor DarkGray }
}
function Safe-Text {
    param($Value)
    if ($null -eq $Value) { return "<empty>" }
    if ($Value -is [System.Array]) {
        if ($Value.Count -eq 0) { return "<empty>" }
        $items = @($Value | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($items.Count -eq 0) { return "<empty>" }
        return ($items -join ", ")
    }
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return "<empty>" }
    return $text.Trim()
}
function Repair-MojibakeUtf8 {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $Text }
    try {
        if ($Text -match 'Ã|ð|ä|å|æ|ç|è|é') {
            $latin1 = [System.Text.Encoding]::GetEncoding(28591)
            $bytes = $latin1.GetBytes($Text)
            $fixed = [System.Text.Encoding]::UTF8.GetString($bytes)
            if (-not [string]::IsNullOrWhiteSpace($fixed)) { return $fixed }
        }
    } catch {}
    return $Text
}
function Read-SavedSecret {
    param([string]$Path)
    $script:SecretLoadError = "<empty>"
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path $Path)) { return "" }
    try {
        $cipher = (Get-Content -Path $Path -Raw -ErrorAction SilentlyContinue)
        if ($cipher) { $cipher = $cipher.Trim() }
        if ([string]::IsNullOrWhiteSpace($cipher)) { return "" }
        $secure = ConvertTo-SecureString -String $cipher
        if ($null -eq $secure) {
            $script:SecretLoadError = "密钥文件格式无效或当前上下文不可解密。"
            return ""
        }
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    } catch {
        $script:SecretLoadError = Safe-Text $_.Exception.Message
        return ""
    }
}
function Save-Secret {
    param([string]$Path,[string]$Secret)
    $script:SecretSaveError = "<empty>"
    if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($Secret)) { return $false }
    try {
        $dir = Split-Path -Path $Path -Parent
        if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
        $secure = ConvertTo-SecureString -String $Secret -AsPlainText -Force
        $cipher = ConvertFrom-SecureString -SecureString $secure
        Set-Content -Path $Path -Value $cipher -Encoding UTF8 -NoNewline
        $verify = Read-SavedSecret -Path $Path
        if ($verify -ne $Secret) {
            $script:SecretSaveError = "写入后回读校验失败（可能是当前运行上下文无法解密）。"
            return $false
        }
        return $true
    } catch {
        $script:SecretSaveError = Safe-Text $_.Exception.Message
        return $false
    }
}
function Select-BestIPv4Interface {
    $candidates = @()
    try {
        $candidates = @(Get-NetIPConfiguration | Where-Object {
            $_.IPv4Address -and $_.NetAdapter -and $_.NetAdapter.Status -eq "Up"
        })
    } catch {}

    if (-not $candidates -or $candidates.Count -eq 0) { return $null }

    $withGateway = @($candidates | Where-Object { $_.IPv4DefaultGateway -and $_.IPv4DefaultGateway.NextHop })
    if ($withGateway.Count -gt 0) {
        return ($withGateway | Sort-Object {
            if ($_.NetIPv4Interface.InterfaceMetric -ne $null) { $_.NetIPv4Interface.InterfaceMetric } else { 9999 }
        } | Select-Object -First 1)
    }

    $routes = @()
    try {
        $routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            Sort-Object RouteMetric, InterfaceMetric)
    } catch {}

    foreach ($route in $routes) {
        $matched = $candidates | Where-Object { $_.InterfaceIndex -eq $route.InterfaceIndex } | Select-Object -First 1
        if ($matched) { return $matched }
    }

    return ($candidates | Sort-Object {
        if ($_.NetIPv4Interface.InterfaceMetric -ne $null) { $_.NetIPv4Interface.InterfaceMetric } else { 9999 }
    } | Select-Object -First 1)
}
function Get-PrimaryAdapterInfo {
    $config = Select-BestIPv4Interface
    if (-not $config) { return $null }

    $dns = @()
    try { $dns = @((Get-DnsClientServerAddress -InterfaceIndex $config.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses) } catch {}

    $gateway = "<empty>"
    try {
        if ($config.IPv4DefaultGateway -and $config.IPv4DefaultGateway.NextHop) {
            $gateway = Safe-Text ($config.IPv4DefaultGateway.NextHop | Select-Object -First 1)
        } else {
            $route = Get-NetRoute -AddressFamily IPv4 -InterfaceIndex $config.InterfaceIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
                Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
            if ($route) { $gateway = Safe-Text $route.NextHop }
        }
    } catch {}

    [pscustomobject]@{
        Alias     = Safe-Text $config.InterfaceAlias
        Desc      = Safe-Text $config.NetAdapter.InterfaceDescription
        IPv4      = Safe-Text ($config.IPv4Address.IPAddress | Select-Object -First 1)
        Gateway   = $gateway
        Dns       = Safe-Text $dns
        Metric    = Safe-Text $config.NetIPv4Interface.InterfaceMetric
        IfIndex   = $config.InterfaceIndex
    }
}
function Invoke-DnsTest {
    param([string]$Domain,[string]$Server,[string]$Label)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $ok = $false
    $ips = New-Object System.Collections.Generic.List[string]
    $err = $null
    try {
        $result = @(Resolve-DnsName -Name $Domain -Server $Server -Type A -DnsOnly -QuickTimeout -ErrorAction Stop)
        foreach ($row in $result) {
            if ($null -ne $row) {
                $props = $row.PSObject.Properties.Name
                if ($props -contains 'IPAddress' -and $row.IPAddress) { [void]$ips.Add([string]$row.IPAddress) }
            }
        }
        if ($ips.Count -gt 0) { $ok = $true }
    } catch {
        $err = $_.Exception.Message
    }
    $sw.Stop()
    [pscustomobject]@{
        Label   = $Label
        Domain  = $Domain
        Server  = $Server
        OK      = $ok
        IPs     = if ($ips.Count -gt 0) { (($ips | Select-Object -Unique) -join ", ") } else { "<empty>" }
        TimeMs  = [int]$sw.Elapsed.TotalMilliseconds
        Error   = Safe-Text $err
    }
}
function Invoke-HttpProbe {
    param([string]$Name,[string]$Url,[string]$Proxy = $null)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $ok = $false
    $statusCode = $null
    $finalUri = $null
    $err = $null
    try {
        $params = @{
            Uri                = $Url
            Method             = "GET"
            MaximumRedirection = 5
            TimeoutSec         = 12
            UseBasicParsing    = $true
            ErrorAction        = 'Stop'
        }
        if ($Proxy) { $params["Proxy"] = $Proxy }
        $resp = Invoke-WebRequest @params
        $statusCode = [int]$resp.StatusCode
        try { $finalUri = Safe-Text $resp.BaseResponse.ResponseUri.AbsoluteUri } catch {}
        if ($statusCode -ge 200 -and $statusCode -lt 400) { $ok = $true }
    } catch {
        $ex = $_.Exception
        try {
            if ($ex.Response -and $ex.Response.StatusCode) { $statusCode = [int]$ex.Response.StatusCode }
        } catch {}
        $err = $ex.Message
    }
    $sw.Stop()
    [pscustomobject]@{
        Name      = $Name
        Url       = $Url
        Proxy     = if ($Proxy) { $Proxy } else { "<none>" }
        OK        = $ok
        Status    = if ($statusCode -ne $null) { [string]$statusCode } else { "<none>" }
        TimeSec   = [math]::Round($sw.Elapsed.TotalSeconds, 2)
        FinalUri  = Safe-Text $finalUri
        Error     = Safe-Text $err
    }
}
function Get-PortInfo {
    param([int]$Port)
    $item = $null
    try { $item = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1) } catch { $item = $null }
    if (-not $item) {
        return [pscustomobject]@{
            Port      = $Port
            Listening = $false
            PID       = "<empty>"
            Process   = "<empty>"
            Path      = "<empty>"
        }
    }
    $procName = "<unknown>"
    $path = "<empty>"
    try {
        $proc = Get-Process -Id $item.OwningProcess -ErrorAction SilentlyContinue
        if ($proc) {
            $procName = Safe-Text $proc.ProcessName
            try { $path = Safe-Text $proc.Path } catch {}
        }
    } catch {}
    [pscustomobject]@{
        Port      = $Port
        Listening = $true
        PID       = [string]$item.OwningProcess
        Process   = $procName
        Path      = $path
    }
}
function Get-SystemProxyInfo {
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    $reg = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
    $winhttp = Safe-Text ((netsh winhttp show proxy | Out-String).Trim())
    [pscustomobject]@{
        ProxyEnable   = if ($null -ne $reg -and $null -ne $reg.ProxyEnable) { [string]$reg.ProxyEnable } else { "0" }
        ProxyServer   = if ($null -ne $reg) { Safe-Text $reg.ProxyServer } else { "<empty>" }
        AutoConfigURL = if ($null -ne $reg) { Safe-Text $reg.AutoConfigURL } else { "<empty>" }
        ProxyOverride = if ($null -ne $reg) { Safe-Text $reg.ProxyOverride } else { "<empty>" }
        WinHTTP       = $winhttp
    }
}
function Get-ServiceStateSafe {
    param([string]$Name)
    try {
        $svc = Get-Service -Name $Name -ErrorAction Stop
        return [pscustomobject]@{ Name = $Name; Exists = $true; Status = Safe-Text $svc.Status; StartType = Safe-Text $svc.StartType }
    } catch {
        return [pscustomobject]@{ Name = $Name; Exists = $false; Status = "<missing>"; StartType = "<missing>" }
    }
}
function Invoke-StoreProbe {
    $targets = @(
        "https://www.msftconnecttest.com/connecttest.txt",
        "https://login.live.com",
        "https://storeedgefd.dsx.mp.microsoft.com",
        "https://displaycatalog.mp.microsoft.com"
    )
    $ok = 0
    $fail = 0
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($u in $targets) {
        $name = ($u -replace '^https?://','')
        $r = Invoke-HttpProbe -Name $name -Url $u
        if ($r.OK) { $ok++ } else { $fail++ }
        [void]$lines.Add(("{0}:{1}({2}s)" -f $name, $(if ($r.OK) { "OK" } else { "FAIL" }), $r.TimeSec))
    }
    [pscustomobject]@{
        OKCount   = $ok
        FailCount = $fail
        Verdict   = if ($ok -ge 3) { "LIKELY_OK" } elseif ($ok -ge 1) { "PARTIAL" } else { "FAIL" }
        Evidence  = if ($lines.Count -gt 0) { $lines -join " || " } else { "<empty>" }
    }
}
function Invoke-ProcessCapture {
    param(
        [string]$FilePath,
        [string[]]$Arguments = @(),
        [int]$TimeoutSec = 8
    )
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $FilePath
        if ($Arguments -and $Arguments.Count -gt 0) {
            $psi.Arguments = [string]::Join(" ", ($Arguments | ForEach-Object {
                if ($_ -match '\s') { '"' + ($_ -replace '"','\"') + '"' } else { $_ }
            }))
        }
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $p = New-Object System.Diagnostics.Process
        $p.StartInfo = $psi
        [void]$p.Start()
        if (-not $p.WaitForExit($TimeoutSec * 1000)) {
            try { $p.Kill() } catch {}
            return [pscustomobject]@{ Ok = $false; TimedOut = $true; ExitCode = -1; StdOut = ""; StdErr = "timeout"; Error = "timeout" }
        }
        return [pscustomobject]@{
            Ok = ($p.ExitCode -eq 0)
            TimedOut = $false
            ExitCode = $p.ExitCode
            StdOut = Safe-Text ($p.StandardOutput.ReadToEnd())
            StdErr = Safe-Text ($p.StandardError.ReadToEnd())
            Error = "<empty>"
        }
    } catch {
        return [pscustomobject]@{ Ok = $false; TimedOut = $false; ExitCode = -1; StdOut = ""; StdErr = ""; Error = Safe-Text $_.Exception.Message }
    }
}
function Invoke-WslProbe {
    $wslCmd = Get-Command wsl.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $wslCmd) {
        return [pscustomobject]@{
            Installed = $false; HasDistro = $false; DistroCount = 0; Distros = "<empty>"; NetworkingMode = "<empty>"
            MirrorMode = "<empty>"; LocalhostForwarding = "<empty>"; Dns = "<empty>"; Net = "<empty>"; Internet = "<empty>"; Verdict = "NO_WSL"; Evidence = "未检测到 wsl.exe"
        }
    }

    $list = Invoke-ProcessCapture -FilePath $wslCmd.Source -Arguments @('-l','-q') -TimeoutSec 6
    $listRaw = ($list.StdOut + " " + $list.StdErr)
    $listText = ((($listRaw -replace "`0","") -replace '\s+',' ').Trim())
    $wslAccessDenied = ($listText -match 'E_ACCESSDENIED|Access\s+is\s+denied|拒绝访问')
    $distros = @()
    if (-not $wslAccessDenied -and $list.StdOut -and $list.StdOut -ne "<empty>") {
        $listOutClean = (($list.StdOut -replace "`0","").Trim())
        $distros = @($listOutClean -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object {
            $_ -and $_ -notmatch 'Windows.*Linux' -and $_ -notmatch '^\s*,$' -and $_ -notmatch 'E_ACCESSDENIED|Access\s+is\s+denied|拒绝访问'
        })
    }
    $status = Invoke-ProcessCapture -FilePath $wslCmd.Source -Arguments @('--status') -TimeoutSec 6
    $statusText = (((($status.StdOut + " " + $status.StdErr) -replace "`0","") -replace '\s+',' ').Trim())
    $netMode = "<empty>"
    if ($statusText -match '(?i)(networking mode|网络模式)\s*[:：]\s*([a-zA-Z]+)') { $netMode = $matches[2] }
    elseif ($statusText -match '(?i)mirrored') { $netMode = "mirrored" }
    elseif ($statusText -match '(?i)\bnat\b') { $netMode = "nat" }

    $localhostForwarding = "<empty>"
    if ($statusText -match '(?i)(localhost.*forwarding|本地主机转发)\s*[:：]\s*(\w+)') { $localhostForwarding = $matches[2] }
    $mirrorMode = "<empty>"
    if (($netMode -replace '\s','').ToLowerInvariant() -eq "mirrored") { $mirrorMode = "YES" }
    elseif (($netMode -replace '\s','').ToLowerInvariant() -eq "nat") { $mirrorMode = "NO" }

    $dnsOk = "<empty>"
    $netOk = "<empty>"
    $evidence = New-Object System.Collections.Generic.List[string]
    if (-not $wslAccessDenied -and $distros.Count -gt 0) {
        $check = Invoke-ProcessCapture -FilePath $wslCmd.Source -Arguments @('-e','sh','-lc','(getent hosts www.msftconnecttest.com >/dev/null 2>&1 || nslookup www.msftconnecttest.com >/dev/null 2>&1) && echo DNS_OK || echo DNS_FAIL; if command -v curl >/dev/null 2>&1; then curl -fsSL -o /dev/null --connect-timeout 4 --max-time 8 https://cp.cloudflare.com/generate_204 && echo NET_OK || echo NET_FAIL; elif command -v wget >/dev/null 2>&1; then wget -q -T 8 -O /dev/null https://cp.cloudflare.com/generate_204 && echo NET_OK || echo NET_FAIL; else ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1 && echo NET_OK || echo NET_FAIL; fi') -TimeoutSec 12
        $txt = ((($check.StdOut + " " + $check.StdErr) -replace "`0",""))
        $txtOneLine = (($txt -replace '\s+',' ').Trim())
        if ($txtOneLine -match 'E_ACCESSDENIED|Access\s+is\s+denied|拒绝访问') { $wslAccessDenied = $true }
        if ($txt -match 'DNS_OK') { $dnsOk = "OK" } elseif ($txt -match 'DNS_FAIL') { $dnsOk = "FAIL" }
        if ($txt -match 'NET_OK') { $netOk = "OK" } elseif ($txt -match 'NET_FAIL') { $netOk = "FAIL" }
        [void]$evidence.Add("check=" + (Safe-Text $txtOneLine))
    }
    $verdict = "UNKNOWN"
    if ($wslAccessDenied) { $verdict = "WSL_ACCESS_DENIED" }
    elseif ($distros.Count -eq 0) { $verdict = "NO_DISTRO" }
    elseif ($netOk -eq "OK") { $verdict = "WSL_OK" }
    elseif ($netOk -eq "FAIL") { $verdict = "WSL_FAIL" }
    else { $verdict = "WSL_PARTIAL" }

    [pscustomobject]@{
        Installed = $true
        HasDistro = ($distros.Count -gt 0)
        DistroCount = $distros.Count
        Distros = if ($distros.Count -gt 0) { ($distros -join ", ") } else { "<empty>" }
        NetworkingMode = Safe-Text $netMode
        MirrorMode = Safe-Text $mirrorMode
        LocalhostForwarding = Safe-Text $localhostForwarding
        Dns = $dnsOk
        Net = $netOk
        Internet = $netOk
        Verdict = $verdict
        Evidence = if ($wslAccessDenied) { "WSL API/服务访问被拒绝（E_ACCESSDENIED）" } elseif ($evidence.Count -gt 0) { $evidence -join " || " } else { "<empty>" }
    }
}
function Invoke-NcsiProbe {
    $dns = Invoke-DnsTest -Domain "dns.msftncsi.com" -Server "223.5.5.5" -Label "NCSI DNS"
    $http = Invoke-HttpProbe -Name "NCSI HTTP" -Url "https://www.msftconnecttest.com/connecttest.txt"
    $txt = "<empty>"
    try {
        $resp = Invoke-WebRequest -Uri "https://www.msftconnecttest.com/connecttest.txt" -Method GET -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop
        $txt = Safe-Text $resp.Content
    } catch {}
    $contentOk = ($txt -match 'Microsoft Connect Test')
    $verdict = if ($dns.OK -and $http.OK -and $contentOk) { "OK" } elseif ($dns.OK -or $http.OK) { "PARTIAL" } else { "FAIL" }
    [pscustomobject]@{
        Verdict = $verdict
        Dns = if ($dns.OK) { "OK" } else { "FAIL" }
        Http = if ($http.OK) { "OK" } else { "FAIL" }
        Content = if ($contentOk) { "OK" } else { "FAIL" }
        Evidence = ("dns={0}; http={1}; content={2}" -f $dns.IPs, $http.Status, $(if ($contentOk) { "match" } else { "mismatch" }))
    }
}
function Get-TlsPolicyProbe {
    $k12 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"
    $k13 = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client"
    $r12 = Get-ItemProperty -Path $k12 -ErrorAction SilentlyContinue
    $r13 = Get-ItemProperty -Path $k13 -ErrorAction SilentlyContinue
    $t12Enabled = $true
    if ($r12) {
        if ($null -ne $r12.Enabled -and [int]$r12.Enabled -eq 0) { $t12Enabled = $false }
        if ($null -ne $r12.DisabledByDefault -and [int]$r12.DisabledByDefault -eq 1) { $t12Enabled = $false }
    }
    $t13Enabled = $true
    if ($r13) {
        if ($null -ne $r13.Enabled -and [int]$r13.Enabled -eq 0) { $t13Enabled = $false }
        if ($null -ne $r13.DisabledByDefault -and [int]$r13.DisabledByDefault -eq 1) { $t13Enabled = $false }
    }
    $live = Invoke-HttpProbe -Name "TLS Probe" -Url "https://login.live.com"
    $timeSvc = Get-ServiceStateSafe -Name "W32Time"
    $verdict = if ($t12Enabled -and $live.OK) { "OK" } elseif (-not $t12Enabled) { "TLS12_DISABLED" } else { "HANDSHAKE_OR_CERT_RISK" }
    [pscustomobject]@{
        Verdict = $verdict
        TLS12 = if ($t12Enabled) { "ENABLED" } else { "DISABLED" }
        TLS13 = if ($t13Enabled) { "ENABLED" } else { "DISABLED" }
        LiveHttps = if ($live.OK) { "OK" } else { "FAIL" }
        LiveStatus = $live.Status
        TimeService = ("{0}/{1}" -f $timeSvc.Status, $timeSvc.StartType)
        Evidence = Safe-Text $live.Error
    }
}
function Get-UpdateChainProbe {
    $names = @("BITS","wuauserv","CryptSvc","UsoSvc","InstallService")
    $rows = @($names | ForEach-Object { Get-ServiceStateSafe -Name $_ })
    $bad = @($rows | Where-Object { -not $_.Exists -or $_.Status -eq "Stopped" -or $_.StartType -eq "Disabled" })
    [pscustomobject]@{
        Verdict = if ($bad.Count -eq 0) { "OK" } elseif ($bad.Count -le 2) { "PARTIAL" } else { "RISK" }
        Evidence = ($rows | ForEach-Object { "{0}:{1}/{2}" -f $_.Name,$_.Status,$_.StartType }) -join " || "
        BadCount = $bad.Count
    }
}
function Get-FirewallSecurityProbe {
    $profiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
    $pfText = if ($profiles.Count -gt 0) { ($profiles | ForEach-Object { "{0}:Enabled={1},Outbound={2}" -f $_.Name,$_.Enabled,$_.DefaultOutboundAction }) -join " || " } else { "<empty>" }
    $allOff = ($profiles.Count -gt 0 -and (@($profiles | Where-Object { $_.Enabled -eq $true }).Count -eq 0))
    $avNames = New-Object System.Collections.Generic.List[string]
    try {
        $avs = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue)
        foreach ($a in $avs) { if ($a.displayName) { [void]$avNames.Add([string]$a.displayName) } }
    } catch {}
    [pscustomobject]@{
        Verdict = if ($allOff) { "FIREWALL_OFF" } else { "OK" }
        Firewall = $pfText
        AV = if ($avNames.Count -gt 0) { ($avNames -join ", ") } else { "<empty>" }
    }
}
function Get-VirtualAdapterInfo {
    $patterns = "wintun|tun|tap|clash|wireguard|tailscale|zerotier|openvpn"
    $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
        $_.Status -eq "Up" -and ($_.Name -match $patterns -or $_.InterfaceDescription -match $patterns)
    })
    $routes = @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -eq "0.0.0.0/0" } |
        Sort-Object RouteMetric, InterfaceMetric)
    $special = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.DestinationPrefix -eq "198.18.0.0/15" } |
        Select-Object -First 1
    [pscustomobject]@{
        VirtualAdapters = $adapters
        DefaultRoutes   = $routes
        Has198Route     = [bool]$special
    }
}
function Get-RoutePrintEvidence {
    $text = ""
    try { $text = (route print | Out-String) } catch { $text = "" }
    $default = New-Object System.Collections.Generic.List[string]
    $section = $false
    foreach ($line in ($text -split "`r?`n")) {
        if ($line -match '^\s*IPv4 Route Table') { continue }
        if ($line -match '^\s*Active Routes:') { $section = $true; continue }
        if ($section -and $line -match '^\s*Persistent Routes:') { break }
        if ($section -and $line -match '^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+') {
            [void]$default.Add(($line.Trim() -replace '\s{2,}', ' | '))
        }
    }
    [pscustomobject]@{
        Raw           = $text
        DefaultRoutes = $default
    }
}
function Invoke-CurlProxyTrace {
    param(
        [string]$Proxy = "http://127.0.0.1:7890",
        [string]$Url = "https://cp.cloudflare.com/generate_204"
    )

    $curlCmd = Get-Command curl.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $curlCmd) {
        return [pscustomobject]@{
            Available = $false; OK = $false; ExitCode = "<empty>"; Status = "<empty>"; RemoteIp = "<empty>"; LocalIp = "<empty>"
            Connects = "<empty>"; TConn = "<empty>"; TTls = "<empty>"; TTotal = "<empty>"; Effective = "<empty>"
            Output = "未找到 curl.exe"; Error = "未找到 curl.exe"; Path = "<empty>"; ConnectedToProxy = $false; TunnelEstablished = $false; TLSOk = $false
        }
    }

    $curlPath = $curlCmd.Source
    $verboseFile = Join-Path $env:TEMP ("curl_verbose_{0}.log" -f ([guid]::NewGuid().ToString("N")))
    $fmt = 'HTTP_CODE=%{http_code}|REMOTE_IP=%{remote_ip}|LOCAL_IP=%{local_ip}|NUM_CONNECTS=%{num_connects}|TIME_CONNECT=%{time_connect}|TIME_APPCONNECT=%{time_appconnect}|TIME_TOTAL=%{time_total}|URL_EFFECTIVE=%{url_effective}'
    $profiles = @(
        @{
            Name = "advanced"
            Args = @('-L','-4','--max-time','20','--connect-timeout','8','-x', $Proxy,'-sS','-o','NUL','-w', $fmt,'-v', $Url)
        },
        @{
            Name = "basic"
            Args = @('-L','--max-time','20','--connect-timeout','8','-x', $Proxy,'-sS','-o','NUL','-w', $fmt,'-v', $Url)
        },
        @{
            Name = "legacy"
            Args = @('-L','--max-time','20','-x', $Proxy,'-sS','-o','NUL','-w', $fmt, $Url)
        }
    )

    $exit = 1
    $metricLine = "<empty>"
    $verbose = "<empty>"
    $attemptSummary = New-Object System.Collections.Generic.List[string]
    foreach ($pf in $profiles) {
        Remove-Item $verboseFile -ErrorAction SilentlyContinue
        $metricText = ""
        try {
            $metricText = & $curlPath @($pf.Args) 2> $verboseFile
            $exit = $LASTEXITCODE
        } catch {
            $metricText = ""
            $exit = 1
        }

        $verboseRaw = Get-Content -Path $verboseFile -Raw -ErrorAction SilentlyContinue
        $thisVerbose = Safe-Text $verboseRaw
        $thisMetric = Safe-Text $metricText
        $thisCode = "<empty>"
        if ($thisMetric -and $thisMetric -ne "<empty>" -and $thisMetric -match 'HTTP_CODE=([0-9]+)') {
            $thisCode = $matches[1]
        }
        [void]$attemptSummary.Add(("{0}(exit={1},code={2})" -f $pf.Name, $exit, $thisCode))
        $verbose = $thisVerbose
        $metricLine = $thisMetric

        if ($exit -eq 0 -and $thisMetric -match 'HTTP_CODE=') { break }
    }

    $map = @{}
    if ($metricLine -and $metricLine -ne "<empty>") {
        foreach ($pair in ($metricLine -split '\|')) {
            $parts = $pair -split '=', 2
            if ($parts.Count -eq 2) { $map[$parts[0]] = $parts[1] }
        }
    }

    $verboseLines = @()
    if ($verbose -and $verbose -ne "<empty>") {
        $all = @($verbose -split "`r?`n")
        $verboseLines = @($all | Where-Object {
            $_ -match 'Connected to ' -or
            $_ -match 'CONNECT ' -or
            $_ -match 'Connection established' -or
            $_ -match 'SSL connection using' -or
            $_ -match 'server certificate' -or
            $_ -match 'Proxy replied' -or
            $_ -match 'Establish HTTP proxy tunnel' -or
            $_ -match 'CONNECT phase completed' -or
            $_ -match 'ALPN' -or
            $_ -match 'Trying '
        } | Select-Object -First 20)
    }

    $trace = if ($verboseLines.Count -gt 0) { ($verboseLines -join ' || ') } else { $verbose }
    if (($trace -eq "<empty>" -or [string]::IsNullOrWhiteSpace($trace)) -and $exit -ne 0) {
        $trace = "curl 无详细输出，可能是参数解析失败或本地 curl 兼容性问题。"
    }
    $connectedToProxy = ($verbose -match 'Connected to 127\.0\.0\.1' -or $verbose -match 'Connected to localhost')
    $tunnelEstablished = ($verbose -match 'CONNECT .*:443' -and $verbose -match '200 Connection established')
    $tlsOk = ($verbose -match 'SSL connection using' -or $verbose -match 'SSL certificate verify ok')
    $remoteIsLocal = ($map.ContainsKey('REMOTE_IP') -and ($map['REMOTE_IP'] -eq '127.0.0.1' -or $map['REMOTE_IP'] -eq '::1'))
    $localIsLocal = ($map.ContainsKey('LOCAL_IP') -and ($map['LOCAL_IP'] -eq '127.0.0.1' -or $map['LOCAL_IP'] -eq '::1'))
    $numConnects = 0
    try { $numConnects = [int]$map['NUM_CONNECTS'] } catch {}
    if (-not $connectedToProxy -and ($remoteIsLocal -or $localIsLocal) -and $numConnects -ge 1) { $connectedToProxy = $true }
    if (-not $tunnelEstablished -and $connectedToProxy -and $exit -eq 0 -and ($map['HTTP_CODE'] -in @('200','204','301','302'))) { $tunnelEstablished = $true }
    if (-not $tlsOk) {
        try {
            $ttls = [double]$map['TIME_APPCONNECT']
            if ($ttls -gt 0) { $tlsOk = $true }
        } catch {}
    }
    $httpOk = ($map['HTTP_CODE'] -in @('200','204','301','302'))
    if ($exit -eq 0 -and $httpOk) {
        $connectedToProxy = $true
        $tunnelEstablished = $true
        $tlsOk = $true
    }

    if ($attemptSummary.Count -gt 0) {
        $trace = "{0} || attempts={1}" -f $trace, ($attemptSummary -join " -> ")
    }

    Remove-Item $verboseFile -ErrorAction SilentlyContinue

    [pscustomobject]@{
        Available         = $true
        Path              = $curlPath
        OK                = ($exit -eq 0 -and ($map['HTTP_CODE'] -in @('200','204','301','302')))
        ExitCode          = [string]$exit
        Status            = Safe-Text $map['HTTP_CODE']
        RemoteIp          = Safe-Text $map['REMOTE_IP']
        LocalIp           = Safe-Text $map['LOCAL_IP']
        Connects          = Safe-Text $map['NUM_CONNECTS']
        TConn             = Safe-Text $map['TIME_CONNECT']
        TTls              = Safe-Text $map['TIME_APPCONNECT']
        TTotal            = Safe-Text $map['TIME_TOTAL']
        Effective         = Safe-Text $map['URL_EFFECTIVE']
        Output            = Safe-Text $trace
        Error             = if ($exit -eq 0) { "<empty>" } else { Safe-Text $verbose }
        ConnectedToProxy  = $connectedToProxy
        TunnelEstablished = $tunnelEstablished
        TLSOk             = $tlsOk
    }
}
function Get-BrowserProfileHints {
    $local = [Environment]::GetFolderPath("LocalApplicationData")
    $chromeBase = Join-Path $local "Google\Chrome\User Data"
    $edgeBase = Join-Path $local "Microsoft\Edge\User Data"

    $chrome = [ordered]@{
        Installed      = Test-Path $chromeBase
        Base           = $chromeBase
        HasPreferences = Test-Path (Join-Path $chromeBase "Default\Preferences")
        HasSecureDns   = $false
        HasProxyHint   = $false
        HasExtensions  = $false
        ExtensionCount = 0
        Evidence       = "<empty>"
    }

    $edge = [ordered]@{
        Installed      = Test-Path $edgeBase
        Base           = $edgeBase
        HasPreferences = Test-Path (Join-Path $edgeBase "Default\Preferences")
        HasSecureDns   = $false
        HasProxyHint   = $false
        HasExtensions  = $false
        ExtensionCount = 0
        Evidence       = "<empty>"
    }

    foreach ($item in @($chrome, $edge)) {
        if ($item.Installed) {
            $pref = Join-Path $item.Base "Default\Preferences"
            if (Test-Path $pref) {
                try {
                    $raw = Get-Content -Path $pref -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
                    if ($raw -match 'dns_over_https' -or $raw -match '"secure_dns"' -or $raw -match '"mode":"secure"') { $item.HasSecureDns = $true }
                    if ($raw -match '"proxy"' -or $raw -match 'proxy_config' -or $raw -match 'proxy.mode') { $item.HasProxyHint = $true }
                    $extDir = Join-Path $item.Base "Default\Extensions"
                    if (Test-Path $extDir) {
                        $dirs = @(Get-ChildItem -Path $extDir -Directory -ErrorAction SilentlyContinue)
                        $item.ExtensionCount = $dirs.Count
                        if ($dirs.Count -gt 0) { $item.HasExtensions = $true }
                    }
                    $item.Evidence = "Preferences=" + $(if ($item.HasPreferences) { "YES" } else { "NO" }) + "; SecureDNSHint=" + $(if ($item.HasSecureDns) { "YES" } else { "NO" }) + "; ProxyHint=" + $(if ($item.HasProxyHint) { "YES" } else { "NO" }) + "; Extensions=" + $item.ExtensionCount
                } catch {
                    $item.Evidence = "读取失败: " + $_.Exception.Message
                }
            } else {
                $item.Evidence = "未找到 Default\\Preferences"
            }
        }
    }

    [pscustomobject]@{
        Chrome = [pscustomobject]$chrome
        Edge   = [pscustomobject]$edge
    }
}
function Invoke-ClashApiProbe {
    param([int]$Port = 9090,[string]$Secret = "")
    $base = "http://127.0.0.1:$Port"
    $headers = @{}
    if ($Secret) { $headers['Authorization'] = "Bearer $Secret" }

    $result = [ordered]@{
        Available     = $false
        AuthRequired  = $false
        HttpStatus    = "<empty>"
        Version       = "<empty>"
        Mode          = "<empty>"
        MixedPort     = "<empty>"
        SocksPort     = "<empty>"
        RedirPort     = "<empty>"
        TProxyPort    = "<empty>"
        AllowLan      = "<empty>"
        LogLevel      = "<empty>"
        TunEnable     = "<empty>"
        SystemProxy   = "<empty>"
        Error         = "<empty>"
    }

    try {
        $versionResp = Invoke-RestMethod -Uri "$base/version" -Headers $headers -TimeoutSec 3 -ErrorAction Stop
        $result.Available = $true
        if ($versionResp.version) { $result.Version = Safe-Text $versionResp.version }
    } catch {
        try {
            if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                $code = [int]$_.Exception.Response.StatusCode
                $result.HttpStatus = [string]$code
                if ($code -eq 401 -or $code -eq 403) { $result.AuthRequired = $true }
            }
        } catch {}
        $result.Error = Safe-Text $_.Exception.Message
        return [pscustomobject]$result
    }

    try {
        $cfg = Invoke-RestMethod -Uri "$base/configs" -Headers $headers -TimeoutSec 3 -ErrorAction Stop
        if ($cfg.mode) { $result.Mode = Safe-Text $cfg.mode }
        if ($cfg.'mixed-port') { $result.MixedPort = Safe-Text $cfg.'mixed-port' }
        if ($cfg.'socks-port') { $result.SocksPort = Safe-Text $cfg.'socks-port' }
        if ($cfg.'redir-port') { $result.RedirPort = Safe-Text $cfg.'redir-port' }
        if ($cfg.'tproxy-port') { $result.TProxyPort = Safe-Text $cfg.'tproxy-port' }
        if ($null -ne $cfg.'allow-lan') { $result.AllowLan = Safe-Text $cfg.'allow-lan' }
        if ($cfg.'log-level') { $result.LogLevel = Safe-Text $cfg.'log-level' }
        if ($null -ne $cfg.'tun' -and $cfg.tun.enable -ne $null) { $result.TunEnable = Safe-Text $cfg.tun.enable }
    } catch {
        if ($result.Error -eq "<empty>") { $result.Error = Safe-Text $_.Exception.Message }
    }

    try {
        $patch = Invoke-RestMethod -Uri "$base/configs" -Method GET -Headers $headers -TimeoutSec 3 -ErrorAction Stop
        if ($null -ne $patch.'system-proxy') { $result.SystemProxy = Safe-Text $patch.'system-proxy' }
    } catch {}

    [pscustomobject]$result
}
function Format-BytesText {
    param([double]$Bytes)
    if ($Bytes -lt 1024) { return ("{0} B" -f [int]$Bytes) }
    if ($Bytes -lt 1MB) { return ("{0:N1} KB" -f ($Bytes / 1KB)) }
    if ($Bytes -lt 1GB) { return ("{0:N2} MB" -f ($Bytes / 1MB)) }
    return ("{0:N2} GB" -f ($Bytes / 1GB))
}
function Get-ClashRuntimeEvidence {
    param([int]$Port = 9090,[string]$Secret = "")
    $base = "http://127.0.0.1:$Port"
    $headers = @{}
    if ($Secret) { $headers['Authorization'] = "Bearer $Secret" }
    $result = [ordered]@{
        Available           = $false
        GroupSelections     = "<empty>"
        AliveProxies        = "<empty>"
        DeadProxies         = "<empty>"
        AliveRatio          = "<empty>"
        ActiveConnections   = "<empty>"
        ThroughputTotal     = "<empty>"
        TopChains           = "<empty>"
        DominantChain       = "<empty>"
        DominantShare       = "<empty>"
        SelectedNodeLatency = "<empty>"
        Error               = "<empty>"
    }
    try {
        $proxiesResp = Invoke-RestMethod -Uri "$base/proxies" -Headers $headers -TimeoutSec 5 -ErrorAction Stop
        $result.Available = $true
        $props = @($proxiesResp.proxies.PSObject.Properties)
        $groupLines = New-Object System.Collections.Generic.List[string]
        $selectedNames = New-Object System.Collections.Generic.List[string]
        $alive = 0
        $dead = 0

        foreach ($pp in $props) {
            $item = $pp.Value
            $name = Repair-MojibakeUtf8 ([string]$pp.Name)
            $hasAll = ($item.PSObject.Properties.Name -contains 'all')
            if ($hasAll -and $item.now) {
                $nowName = Repair-MojibakeUtf8 (Safe-Text $item.now)
                [void]$groupLines.Add(("{0} -> {1} ({2})" -f $name, $nowName, (Safe-Text $item.type)))
                [void]$selectedNames.Add([string]$item.now)
            } elseif ($item.PSObject.Properties.Name -contains 'alive') {
                if ($item.alive -eq $true) { $alive++ } elseif ($item.alive -eq $false) { $dead++ }
            }
        }

        if ($groupLines.Count -gt 0) { $result.GroupSelections = (($groupLines | Select-Object -First 8) -join " || ") }
        $result.AliveProxies = [string]$alive
        $result.DeadProxies = [string]$dead
        $total = $alive + $dead
        if ($total -gt 0) { $result.AliveRatio = ("{0:P0}" -f ($alive / [double]$total)) }

        $latencyLines = New-Object System.Collections.Generic.List[string]
        foreach ($sn in ($selectedNames | Select-Object -Unique | Select-Object -First 8)) {
            if ($proxiesResp.proxies.PSObject.Properties.Name -contains $sn) {
                $node = $proxiesResp.proxies.$sn
                $delay = "<empty>"
                if ($node -and $node.history) {
                    $lastDelay = $node.history | Select-Object -Last 1
                    if ($lastDelay -and $lastDelay.delay -ne $null) { $delay = [string]$lastDelay.delay }
                }
                [void]$latencyLines.Add(("{0}:{1}ms" -f (Repair-MojibakeUtf8 $sn), $delay))
            }
        }
        if ($latencyLines.Count -gt 0) { $result.SelectedNodeLatency = ($latencyLines -join " || ") }
    } catch {
        $result.Error = Safe-Text $_.Exception.Message
        return [pscustomobject]$result
    }

    try {
        $connResp = Invoke-RestMethod -Uri "$base/connections" -Headers $headers -TimeoutSec 5 -ErrorAction Stop
        $connCount = @($connResp.connections).Count
        $result.ActiveConnections = [string]$connCount
        $result.ThroughputTotal = ("UP={0}, DOWN={1}" -f (Format-BytesText ([double]$connResp.uploadTotal)), (Format-BytesText ([double]$connResp.downloadTotal)))
        if ($connCount -gt 0) {
            $grouped = @($connResp.connections | Group-Object { ($_.'chains' | ForEach-Object { [string]$_ }) -join " > " } | Sort-Object Count -Descending)
            $top = @($grouped | Select-Object -First 5 | ForEach-Object {
                "{0}x {1}" -f $_.Count, (Repair-MojibakeUtf8 (Safe-Text $_.Name))
            })
            if ($top.Count -gt 0) { $result.TopChains = ($top -join " || ") }
            if ($grouped.Count -gt 0) {
                $first = $grouped[0]
                $result.DominantChain = Repair-MojibakeUtf8 (Safe-Text $first.Name)
                $result.DominantShare = ("{0:P0}" -f ($first.Count / [double]$connCount))
            }
        }
    } catch {}

    return [pscustomobject]$result
}
function Get-BrowserRisk {
    param($ProxyInfo,$ProxyHttpGoogle,$Port7890,$BrowserHints)
    $risk = New-Object System.Collections.Generic.List[string]

    if ($ProxyInfo.ProxyEnable -ne "1") { [void]$risk.Add("系统代理未启用，浏览器若跟随系统代理则不会走 Clash。") }
    if ($Port7890.Listening -and $ProxyHttpGoogle.OK -and $ProxyInfo.ProxyEnable -ne "1") { [void]$risk.Add("代理端口和代理链路正常，但浏览器仍可能没有走代理。") }
    if ($BrowserHints.Chrome.Installed) {
        if ($BrowserHints.Chrome.HasSecureDns) { [void]$risk.Add("Chrome 检测到 Secure DNS 迹象，域名解析可能绕过 Clash DNS。") }
        if ($BrowserHints.Chrome.HasProxyHint) { [void]$risk.Add("Chrome Preferences 中出现 proxy 相关字段，可能存在独立代理配置或扩展接管。") }
        if ($BrowserHints.Chrome.HasExtensions) { [void]$risk.Add("Chrome 存在扩展，代理扩展或隐私扩展可能覆盖代理行为。") }
    }
    if ($BrowserHints.Edge.Installed) {
        if ($BrowserHints.Edge.HasSecureDns) { [void]$risk.Add("Edge 检测到 Secure DNS 迹象，域名解析可能绕过 Clash DNS。") }
        if ($BrowserHints.Edge.HasProxyHint) { [void]$risk.Add("Edge Preferences 中出现 proxy 相关字段，可能存在独立代理配置或扩展接管。") }
        if ($BrowserHints.Edge.HasExtensions) { [void]$risk.Add("Edge 存在扩展，代理扩展或隐私扩展可能覆盖代理行为。") }
    }
    [void]$risk.Add("浏览器 QUIC / HTTP3 可能与部分代理链路兼容性不佳。")
    [void]$risk.Add("PAC、SwitchyOmega、广告拦截扩展、隐私扩展可能覆盖代理行为。")
    return $risk
}
function Save-Report {
    param([string]$Path)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("==========================================================") | Out-Null
    $lines.Add(" Clash / Network Doctor for Windows") | Out-Null
    $lines.Add(" Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')") | Out-Null
    $lines.Add("==========================================================") | Out-Null
    $lines.Add("") | Out-Null
    $lines.Add("[SUMMARY]") | Out-Null
    foreach ($k in $script:Summary.Keys) { $lines.Add(("{0,-30}: {1}" -f $k, $script:Summary[$k])) | Out-Null }
    $lines.Add("") | Out-Null
    $lines.Add("[DETAILS]") | Out-Null
    foreach ($d in $script:Details) { $lines.Add($d) | Out-Null }
    $lines.Add("") | Out-Null
    $lines.Add("[DIAGNOSIS]") | Out-Null
    $i = 1
    foreach ($d in $script:Diagnosis) { $lines.Add(("{0}. {1}" -f $i, $d)) | Out-Null; $i++ }
    $lines.Add("") | Out-Null
    $lines.Add("[SUGGESTIONS]") | Out-Null
    $i = 1
    foreach ($s in $script:Suggestions) { $lines.Add(("{0}. {1}" -f $i, $s)) | Out-Null; $i++ }
    Set-Content -Path $Path -Value $lines -Encoding UTF8
}

Clear-Host
Write-Host "Clash / Network Doctor for Windows" -ForegroundColor Cyan
Write-Host ("开始时间: {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss")) -ForegroundColor DarkGray

$proxyUri = "http://{0}:{1}" -f $ProxyHost, $ProxyPort
$scriptDir = if ($PSScriptRoot -and (Test-Path $PSScriptRoot)) { $PSScriptRoot } else { (Get-Location).Path }
$defaultReportRoot = Join-Path $scriptDir "Clash_Network_Doctor_Reports"
$effectiveReportRoot = if ([string]::IsNullOrWhiteSpace($ReportRoot)) { $defaultReportRoot } else { $ReportRoot }
$defaultSecretStorePath = Join-Path $scriptDir ".clash_api_secret.dat"
$effectiveSecretStorePath = if ([string]::IsNullOrWhiteSpace($SecretStorePath)) { $defaultSecretStorePath } else { $SecretStorePath }
$secretSource = "none"
$savedSecretUpdated = $false
if ($ForgetSavedSecret) { Remove-Item -Path $effectiveSecretStorePath -ErrorAction SilentlyContinue }
$effectiveClashSecret = $ClashSecret
if (-not [string]::IsNullOrWhiteSpace($effectiveClashSecret)) {
    $secretSource = "param"
} else {
    $loadedSecret = Read-SavedSecret -Path $effectiveSecretStorePath
    if (-not [string]::IsNullOrWhiteSpace($loadedSecret)) {
        $effectiveClashSecret = $loadedSecret
        $secretSource = "saved"
    }
}
$runFolder = Join-Path $effectiveReportRoot ("Run_{0}" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
New-Item -Path $runFolder -ItemType Directory -Force | Out-Null
$reportFile = Join-Path $runFolder ("Clash_Network_Doctor_{0}.txt" -f (Get-Date -Format "yyyyMMdd_HHmmss"))

$nic = Get-PrimaryAdapterInfo
$proxyInfo = Get-SystemProxyInfo
$port7890 = Get-PortInfo -Port $ProxyPort
$port7891 = Get-PortInfo -Port $MixedPort
$port9090 = Get-PortInfo -Port $ApiPort
$knownApiPorts = @(9090, 9097, 9095, 9094, 9091) | Select-Object -Unique
$apiAltListeningPorts = New-Object System.Collections.Generic.List[int]
foreach ($candidate in $knownApiPorts) {
    if ($candidate -eq $ApiPort) { continue }
    $p = Get-PortInfo -Port $candidate
    if ($p.Listening) { [void]$apiAltListeningPorts.Add($candidate) }
}
$apiPidListeningPorts = New-Object System.Collections.Generic.List[int]
if ($port7890.Listening -and $port7890.PID -ne "<empty>") {
    try {
        $pidValue = [int]$port7890.PID
        $pidPorts = @(Get-NetTCPConnection -State Listen -OwningProcess $pidValue -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LocalPort -Unique)
        foreach ($p in $pidPorts) {
            if ($p -ne $ProxyPort -and $p -ne $MixedPort) {
                [void]$apiPidListeningPorts.Add([int]$p)
            }
        }
    } catch {}
}
$candidateApiPorts = New-Object System.Collections.Generic.List[int]
foreach ($p in @($ApiPort)) { if (-not $candidateApiPorts.Contains($p)) { [void]$candidateApiPorts.Add($p) } }
foreach ($p in $knownApiPorts) { if (-not $candidateApiPorts.Contains($p)) { [void]$candidateApiPorts.Add($p) } }
foreach ($p in $apiPidListeningPorts) { if (-not $candidateApiPorts.Contains($p)) { [void]$candidateApiPorts.Add($p) } }
$apiProbeAttempts = New-Object System.Collections.Generic.List[string]
$apiAuthRequiredPorts = New-Object System.Collections.Generic.List[int]
$apiProbePort = $ApiPort
$clashApi = $null
foreach ($p in $candidateApiPorts) {
    $probe = Invoke-ClashApiProbe -Port $p -Secret $effectiveClashSecret
    $attempt = "{0}:{1}" -f $p, $(if ($probe.Available) { "OK" } else { Safe-Text $probe.Error })
    [void]$apiProbeAttempts.Add($attempt)
    if ($probe.Available) {
        $apiProbePort = $p
        $clashApi = $probe
        break
    }
    if ($probe.AuthRequired) {
        [void]$apiAuthRequiredPorts.Add($p)
        $apiProbePort = $p
        $clashApi = $probe
        break
    }
}
if (-not $clashApi) {
    $apiProbePort = $candidateApiPorts[0]
    $clashApi = Invoke-ClashApiProbe -Port $apiProbePort -Secret $effectiveClashSecret
    if ($clashApi.AuthRequired -and -not $apiAuthRequiredPorts.Contains($apiProbePort)) { [void]$apiAuthRequiredPorts.Add($apiProbePort) }
}
if ($clashApi.AuthRequired -and [string]::IsNullOrWhiteSpace($effectiveClashSecret) -and -not $NoSecretPrompt -and [Environment]::UserInteractive) {
    $typedSecret = Read-Host -Prompt "检测到 Clash API 需要访问密钥，请输入（留空则跳过）"
    if (-not [string]::IsNullOrWhiteSpace($typedSecret)) {
        $effectiveClashSecret = $typedSecret
        $secretSource = "prompt"
        $apiProbeAttempts = New-Object System.Collections.Generic.List[string]
        $apiAuthRequiredPorts = New-Object System.Collections.Generic.List[int]
        $apiProbePort = $ApiPort
        $clashApi = $null
        foreach ($p in $candidateApiPorts) {
            $probe = Invoke-ClashApiProbe -Port $p -Secret $effectiveClashSecret
            $attempt = "{0}:{1}" -f $p, $(if ($probe.Available) { "OK" } else { Safe-Text $probe.Error })
            [void]$apiProbeAttempts.Add($attempt)
            if ($probe.Available) {
                $apiProbePort = $p
                $clashApi = $probe
                break
            }
            if ($probe.AuthRequired) {
                [void]$apiAuthRequiredPorts.Add($p)
                $apiProbePort = $p
                $clashApi = $probe
                break
            }
        }
        if (-not $clashApi) {
            $apiProbePort = $candidateApiPorts[0]
            $clashApi = Invoke-ClashApiProbe -Port $apiProbePort -Secret $effectiveClashSecret
            if ($clashApi.AuthRequired -and -not $apiAuthRequiredPorts.Contains($apiProbePort)) { [void]$apiAuthRequiredPorts.Add($apiProbePort) }
        }
        if ($clashApi.Available) {
            $savedSecretUpdated = Save-Secret -Path $effectiveSecretStorePath -Secret $effectiveClashSecret
            if ($savedSecretUpdated) { $secretSource = "prompt_saved" }
        }
    }
}
$apiAnyListening = ($port9090.Listening -or $apiAltListeningPorts.Count -gt 0 -or $apiPidListeningPorts.Count -gt 0 -or $apiAuthRequiredPorts.Count -gt 0)
if ($clashApi.Available -and -not [string]::IsNullOrWhiteSpace($effectiveClashSecret) -and $secretSource -eq "param") {
    $savedSecretUpdated = Save-Secret -Path $effectiveSecretStorePath -Secret $effectiveClashSecret
}
$clashRuntime = if ($clashApi.Available) { Get-ClashRuntimeEvidence -Port $apiProbePort -Secret $effectiveClashSecret } else { [pscustomobject]@{ Available = $false; GroupSelections = "<empty>"; AliveProxies = "<empty>"; DeadProxies = "<empty>"; AliveRatio = "<empty>"; ActiveConnections = "<empty>"; ThroughputTotal = "<empty>"; TopChains = "<empty>"; SelectedNodeLatency = "<empty>"; Error = "<empty>" } }
$virtualInfo = Get-VirtualAdapterInfo
$routePrint = Get-RoutePrintEvidence
$browserHints = Get-BrowserProfileHints
$wslProbe = Invoke-WslProbe
$ncsiProbe = Invoke-NcsiProbe
$tlsProbe = Get-TlsPolicyProbe
$updateProbe = Get-UpdateChainProbe
$fwProbe = Get-FirewallSecurityProbe
$svcBITS = Get-ServiceStateSafe -Name "BITS"
$svcClip = Get-ServiceStateSafe -Name "ClipSVC"
$svcInstall = Get-ServiceStateSafe -Name "InstallService"
$svcWua = Get-ServiceStateSafe -Name "wuauserv"
$storeProbe = Invoke-StoreProbe

$dnsCn = Invoke-DnsTest -Domain "www.baidu.com" -Server "223.5.5.5" -Label "CN DNS"
$dnsGlobal = Invoke-DnsTest -Domain "www.google.com" -Server "8.8.8.8" -Label "GLOBAL DNS"

$httpBaidu = Invoke-HttpProbe -Name "CN HTTP" -Url "https://www.baidu.com"
$httpGoogleDirect = Invoke-HttpProbe -Name "Global Direct HTTP" -Url "https://www.google.com/generate_204"
$httpCloudflareProxy = Invoke-HttpProbe -Name "Clash Proxy HTTP" -Url "https://cp.cloudflare.com/generate_204" -Proxy $proxyUri
$httpGoogleProxy = Invoke-HttpProbe -Name "Clash Google Proxy" -Url "https://www.google.com/generate_204" -Proxy $proxyUri
$curlTrace = Invoke-CurlProxyTrace -Proxy $proxyUri -Url "https://cp.cloudflare.com/generate_204"

$browserRisk = Get-BrowserRisk -ProxyInfo $proxyInfo -ProxyHttpGoogle $httpGoogleProxy -Port7890 $port7890 -BrowserHints $browserHints

$localNetworkStatus = if ($nic -and $nic.IPv4 -ne "<empty>" -and $nic.Gateway -ne "<empty>") { "OK" } elseif ($httpBaidu.OK) { "PARTIAL" } else { "FAIL" }
$chinaDnsStatus = if ($dnsCn.OK) { "OK" } else { "FAIL" }
$globalDnsStatus = if ($dnsGlobal.OK) { "OK" } else { "FAIL" }
$chinaHttpStatus = if ($httpBaidu.OK) { "OK" } else { "FAIL" }
$globalDirectHttpStatus = if ($httpGoogleDirect.OK) { "OK" } else { "FAIL" }
$clashPortStatus = if ($port7890.Listening) { "OK" } else { "FAIL" }
$clashProxyHttpStatus = if ($httpCloudflareProxy.OK -or $httpGoogleProxy.OK) { "OK" } else { "FAIL" }
$curlProxyStatus = if ($curlTrace.Available -and $curlTrace.OK) { "OK" } elseif (-not $curlTrace.Available) { "UNKNOWN" } else { "FAIL" }
$systemProxyStatus = if ($proxyInfo.ProxyEnable -eq "1") { "ENABLED" } else { "DISABLED" }
$clashApiStatus = if ($clashApi.Available) { "OK" } elseif ($clashApi.AuthRequired -or $apiAuthRequiredPorts.Count -gt 0) { "AUTH_REQUIRED" } elseif ($apiAnyListening) { "AUTH_OR_API_ERROR" } else { "UNAVAILABLE" }
$browserRiskStatus = if ($proxyInfo.ProxyEnable -eq "1" -and ($httpGoogleProxy.OK -or $httpCloudflareProxy.OK)) { "MEDIUM" } else { "HIGH" }
$winHttpStatus = if ($proxyInfo.WinHTTP -match 'Direct access') { "DIRECT" } else { "PROXY_OR_AUTO" }
$storeStatus = $storeProbe.Verdict
$wslStatus = $wslProbe.Verdict
$ncsiStatus = $ncsiProbe.Verdict
$tlsStatus = $tlsProbe.Verdict
$updateStatus = $updateProbe.Verdict
$firewallStatus = $fwProbe.Verdict
$networkPathMode = if ($clashApi.Available) { Safe-Text $clashApi.Mode } else { "<empty>" }
$networkPathTun = if ($clashApi.Available) { Safe-Text $clashApi.TunEnable } else { "<empty>" }
$networkPathSystemProxy = if ($proxyInfo.ProxyEnable -eq "1") { "ON" } else { "OFF" }
$networkPathVerdict = "<empty>"
if ($clashApi.Available) {
    $modeLower = ([string]$clashApi.Mode).ToLowerInvariant()
    $tunOn = (([string]$clashApi.TunEnable).ToLowerInvariant() -eq "true")
    if ($tunOn) {
        $networkPathVerdict = "TUN 模式接管流量（系统全局更接近 VPN 路径）"
    } elseif ($modeLower -eq "global") {
        $networkPathVerdict = "GLOBAL 全局代理模式（主要按 GLOBAL 策略组出口）"
    } elseif ($modeLower -eq "rule") {
        $networkPathVerdict = "RULE 分流模式（按规则命中，非所有流量都走代理）"
    } elseif ($modeLower -eq "direct") {
        $networkPathVerdict = "DIRECT 直连模式（默认不走代理）"
    } else {
        $networkPathVerdict = "模式未知，需看 Clash 配置"
    }
}

Add-Summary "Local Network" $localNetworkStatus
Add-Summary "China DNS" $chinaDnsStatus
Add-Summary "Global DNS" $globalDnsStatus
Add-Summary "China HTTP" $chinaHttpStatus
Add-Summary "Global Direct HTTP" $globalDirectHttpStatus
Add-Summary "Clash Port $ProxyPort" $clashPortStatus
Add-Summary "Clash Proxy HTTP" $clashProxyHttpStatus
Add-Summary "curl Proxy Trace" $curlProxyStatus
Add-Summary "Clash API" $clashApiStatus
Add-Summary "System Proxy" $systemProxyStatus
Add-Summary "Browser Risk" $browserRiskStatus
Add-Summary "WinHTTP Profile" $winHttpStatus
Add-Summary "Microsoft Store" $storeStatus
Add-Summary "WSL Network" $wslStatus
Add-Summary "NCSI Health" $ncsiStatus
Add-Summary "TLS/Cert" $tlsStatus
Add-Summary "Update Chain" $updateStatus
Add-Summary "Firewall/Security" $firewallStatus

Add-Detail ("Adapter                     : {0}" -f $(if ($nic) { $nic.Alias } else { "<not found>" }))
Add-Detail ("Description                 : {0}" -f $(if ($nic) { $nic.Desc } else { "<empty>" }))
Add-Detail ("IPv4                        : {0}" -f $(if ($nic) { $nic.IPv4 } else { "<empty>" }))
Add-Detail ("Gateway                     : {0}" -f $(if ($nic) { $nic.Gateway } else { "<empty>" }))
Add-Detail ("DNS Servers                 : {0}" -f $(if ($nic) { $nic.Dns } else { "<empty>" }))
Add-Detail ("Interface Metric            : {0}" -f $(if ($nic) { $nic.Metric } else { "<empty>" }))

Add-Detail ""
Add-Detail ("Port {0}                    : {1}" -f $ProxyPort, $(if ($port7890.Listening) { "LISTENING" } else { "NOT LISTENING" }))
Add-Detail ("PID                         : {0}" -f $port7890.PID)
Add-Detail ("Process                     : {0}" -f $port7890.Process)
Add-Detail ("Path                        : {0}" -f $port7890.Path)
Add-Detail ("Port {0}                    : {1}" -f $MixedPort, $(if ($port7891.Listening) { "LISTENING" } else { "NOT LISTENING" }))
Add-Detail ("Port {0}                    : {1}" -f $ApiPort, $(if ($port9090.Listening) { "LISTENING" } else { "NOT LISTENING" }))
Add-Detail ("Clash API Probe Port        : {0}" -f $apiProbePort)
Add-Detail ("Clash API Alt Listening     : {0}" -f $(if ($apiAltListeningPorts.Count -gt 0) { (($apiAltListeningPorts | ForEach-Object { [string]$_ }) -join ", ") } else { "<empty>" }))
Add-Detail ("Clash PID Listen Ports      : {0}" -f $(if ($apiPidListeningPorts.Count -gt 0) { (($apiPidListeningPorts | Sort-Object -Unique | ForEach-Object { [string]$_ }) -join ", ") } else { "<empty>" }))
Add-Detail ("Clash API Probe Attempts    : {0}" -f $(if ($apiProbeAttempts.Count -gt 0) { (($apiProbeAttempts | Select-Object -First 8) -join " || ") } else { "<empty>" }))
Add-Detail ("Clash Secret Source         : {0}" -f $secretSource)
Add-Detail ("Clash Secret Store Path     : {0}" -f $effectiveSecretStorePath)
Add-Detail ("Clash Secret Saved          : {0}" -f $(if ($savedSecretUpdated) { "YES" } else { "NO" }))
Add-Detail ("Clash Secret Load Error     : {0}" -f $script:SecretLoadError)
Add-Detail ("Clash Secret Save Error     : {0}" -f $script:SecretSaveError)
Add-Detail ("Report Output Folder        : {0}" -f $runFolder)

Add-Detail ""
Add-Detail ("System ProxyEnable          : {0}" -f $proxyInfo.ProxyEnable)
Add-Detail ("System ProxyServer          : {0}" -f $proxyInfo.ProxyServer)
Add-Detail ("System AutoConfigURL        : {0}" -f $proxyInfo.AutoConfigURL)
Add-Detail ("System ProxyOverride        : {0}" -f $proxyInfo.ProxyOverride)
Add-Detail ("WinHTTP Proxy               : {0}" -f $proxyInfo.WinHTTP.Replace([Environment]::NewLine, " | "))
Add-Detail ("System Proxy Verdict        : {0}" -f $(if ($proxyInfo.ProxyEnable -eq "1") { "地址与开关均生效" } elseif ($proxyInfo.ProxyServer -ne "<empty>") { "地址已写入，但开关未启用" } else { "未配置代理地址且未启用" }))
Add-Detail ("WinHTTP Profile            : {0}" -f $winHttpStatus)

Add-Detail ""
Add-Detail ("DNS Test (Baidu)            : {0} via {1} in {2} ms" -f $dnsCn.IPs, $dnsCn.Server, $dnsCn.TimeMs)
if (-not $dnsCn.OK) { Add-Detail ("DNS Error (Baidu)           : {0}" -f $dnsCn.Error) }
Add-Detail ("DNS Test (Google)           : {0} via {1} in {2} ms" -f $dnsGlobal.IPs, $dnsGlobal.Server, $dnsGlobal.TimeMs)
if (-not $dnsGlobal.OK) { Add-Detail ("DNS Error (Google)          : {0}" -f $dnsGlobal.Error) }

Add-Detail ""
Add-Detail ("HTTP Test (Baidu)           : status {0} in {1}s" -f $httpBaidu.Status, $httpBaidu.TimeSec)
if (-not $httpBaidu.OK) { Add-Detail ("HTTP Error (Baidu)          : {0}" -f $httpBaidu.Error) }
Add-Detail ("HTTP Test (Google)          : status {0} direct in {1}s" -f $httpGoogleDirect.Status, $httpGoogleDirect.TimeSec)
if (-not $httpGoogleDirect.OK) { Add-Detail ("HTTP Error (Google)         : {0}" -f $httpGoogleDirect.Error) }
Add-Detail ("HTTP Proxy Test (CF)        : status {0} via {1} in {2}s" -f $httpCloudflareProxy.Status, $httpCloudflareProxy.Proxy, $httpCloudflareProxy.TimeSec)
if (-not $httpCloudflareProxy.OK) { Add-Detail ("HTTP Proxy Error (CF)       : {0}" -f $httpCloudflareProxy.Error) }
Add-Detail ("HTTP Proxy Test (G)         : status {0} via {1} in {2}s" -f $httpGoogleProxy.Status, $httpGoogleProxy.Proxy, $httpGoogleProxy.TimeSec)
if (-not $httpGoogleProxy.OK) { Add-Detail ("HTTP Proxy Error (G)        : {0}" -f $httpGoogleProxy.Error) }

Add-Detail ""
Add-Detail ("curl.exe Path               : {0}" -f $curlTrace.Path)
Add-Detail ("curl Proxy Trace            : {0}" -f $(if ($curlTrace.Available) { $(if ($curlTrace.OK) { "SUCCESS" } else { "FAIL" }) } else { "UNAVAILABLE" }))
Add-Detail ("curl ExitCode               : {0}" -f $curlTrace.ExitCode)
Add-Detail ("curl HTTP Code              : {0}" -f $curlTrace.Status)
Add-Detail ("curl Remote IP              : {0}" -f $curlTrace.RemoteIp)
Add-Detail ("curl Local IP               : {0}" -f $curlTrace.LocalIp)
Add-Detail ("curl Connect Count          : {0}" -f $curlTrace.Connects)
Add-Detail ("curl Time Connect           : {0}" -f $curlTrace.TConn)
Add-Detail ("curl Time TLS               : {0}" -f $curlTrace.TTls)
Add-Detail ("curl Time Total             : {0}" -f $curlTrace.TTotal)
Add-Detail ("curl Effective URL          : {0}" -f $curlTrace.Effective)
Add-Detail ("curl ConnectedToProxy       : {0}" -f $(if ($curlTrace.ConnectedToProxy) { "YES" } else { "NO" }))
Add-Detail ("curl CONNECT Established    : {0}" -f $(if ($curlTrace.TunnelEstablished) { "YES" } else { "NO" }))
Add-Detail ("curl TLS Established        : {0}" -f $(if ($curlTrace.TLSOk) { "YES" } else { "NO" }))
Add-Detail ("curl Verbose Trace          : {0}" -f $curlTrace.Output)
if (-not $curlTrace.OK -and $curlTrace.Available) { Add-Detail ("curl Trace Error            : {0}" -f $curlTrace.Error) }

Add-Detail ""
if ($virtualInfo.VirtualAdapters -and $virtualInfo.VirtualAdapters.Count -gt 0) {
    foreach ($va in $virtualInfo.VirtualAdapters) {
        Add-Detail ("Virtual Adapter            : {0} / {1}" -f (Safe-Text $va.Name), (Safe-Text $va.InterfaceDescription))
    }
} else {
    Add-Detail "Virtual Adapter            : <not found>"
}
if ($virtualInfo.DefaultRoutes -and $virtualInfo.DefaultRoutes.Count -gt 0) {
    $i = 1
    foreach ($route in $virtualInfo.DefaultRoutes | Select-Object -First 8) {
        Add-Detail ("Default Route #{0}         : NextHop={1}; IfIndex={2}; RouteMetric={3}; InterfaceMetric={4}" -f $i, (Safe-Text $route.NextHop), (Safe-Text $route.InterfaceIndex), (Safe-Text $route.RouteMetric), (Safe-Text $route.InterfaceMetric))
        $i++
    }
}
Add-Detail ("Has 198.18.0.0/15          : {0}" -f $(if ($virtualInfo.Has198Route) { "YES" } else { "NO" }))

Add-Detail ""
if ($routePrint.DefaultRoutes.Count -gt 0) {
    $idx = 1
    foreach ($line in $routePrint.DefaultRoutes | Select-Object -First 8) {
        Add-Detail ("route print #{0}           : {1}" -f $idx, $line)
        $idx++
    }
} else {
    Add-Detail "route print default        : <not found>"
}

Add-Detail ""
Add-Detail ("Chrome Installed           : {0}" -f $(if ($browserHints.Chrome.Installed) { "YES" } else { "NO" }))
Add-Detail ("Chrome Risk Evidence       : {0}" -f $browserHints.Chrome.Evidence)
Add-Detail ("Edge Installed             : {0}" -f $(if ($browserHints.Edge.Installed) { "YES" } else { "NO" }))
Add-Detail ("Edge Risk Evidence         : {0}" -f $browserHints.Edge.Evidence)
Add-Detail ("Service BITS              : {0}/{1}" -f $svcBITS.Status, $svcBITS.StartType)
Add-Detail ("Service ClipSVC           : {0}/{1}" -f $svcClip.Status, $svcClip.StartType)
Add-Detail ("Service InstallService    : {0}/{1}" -f $svcInstall.Status, $svcInstall.StartType)
Add-Detail ("Service wuauserv          : {0}/{1}" -f $svcWua.Status, $svcWua.StartType)
Add-Detail ("Store Probe Verdict       : {0}" -f $storeProbe.Verdict)
Add-Detail ("Store Probe Evidence      : {0}" -f $storeProbe.Evidence)
Add-Detail ("WSL Installed             : {0}" -f $(if ($wslProbe.Installed) { "YES" } else { "NO" }))
Add-Detail ("WSL Distros               : {0}" -f $wslProbe.Distros)
Add-Detail ("WSL NetworkingMode        : {0}" -f $wslProbe.NetworkingMode)
Add-Detail ("WSL MirrorMode            : {0}" -f $wslProbe.MirrorMode)
Add-Detail ("WSL Internet(HTTPS)       : {0}" -f $wslProbe.Internet)
Add-Detail ("WSL DNS Check             : {0}" -f $wslProbe.Dns)
Add-Detail ("WSL Probe Verdict         : {0}" -f $wslProbe.Verdict)
Add-Detail ("WSL Probe Evidence        : {0}" -f $wslProbe.Evidence)
Add-Detail ("NCSI Verdict              : {0}" -f $ncsiProbe.Verdict)
Add-Detail ("NCSI Evidence             : {0}" -f $ncsiProbe.Evidence)
Add-Detail ("TLS Policy                : TLS1.2={0}; TLS1.3={1}; LiveHttps={2}/{3}" -f $tlsProbe.TLS12, $tlsProbe.TLS13, $tlsProbe.LiveHttps, $tlsProbe.LiveStatus)
Add-Detail ("TLS TimeService           : {0}" -f $tlsProbe.TimeService)
Add-Detail ("TLS Evidence              : {0}" -f $tlsProbe.Evidence)
Add-Detail ("Update Chain Verdict      : {0}" -f $updateProbe.Verdict)
Add-Detail ("Update Chain Evidence     : {0}" -f $updateProbe.Evidence)
Add-Detail ("Firewall Verdict          : {0}" -f $fwProbe.Verdict)
Add-Detail ("Firewall Profiles         : {0}" -f $fwProbe.Firewall)
Add-Detail ("Security AV Products      : {0}" -f $fwProbe.AV)

Add-Detail ""
Add-Detail ("Clash API Available        : {0}" -f $(if ($clashApi.Available) { "YES" } else { "NO" }))
Add-Detail ("Clash API Version          : {0}" -f $clashApi.Version)
Add-Detail ("Clash API Mode             : {0}" -f $clashApi.Mode)
Add-Detail ("Clash API MixedPort        : {0}" -f $clashApi.MixedPort)
Add-Detail ("Clash API SocksPort        : {0}" -f $clashApi.SocksPort)
Add-Detail ("Clash API RedirPort        : {0}" -f $clashApi.RedirPort)
Add-Detail ("Clash API TProxyPort       : {0}" -f $clashApi.TProxyPort)
Add-Detail ("Clash API AllowLan         : {0}" -f $clashApi.AllowLan)
Add-Detail ("Clash API LogLevel         : {0}" -f $clashApi.LogLevel)
Add-Detail ("Clash API TunEnable        : {0}" -f $clashApi.TunEnable)
Add-Detail ("Clash API SystemProxy      : {0}" -f $clashApi.SystemProxy)
if (-not $clashApi.Available -and $clashApi.Error -ne "<empty>") { Add-Detail ("Clash API Error            : {0}" -f $clashApi.Error) }
if ($clashRuntime.Available) {
    Add-Detail ("Clash Runtime Groups       : {0}" -f $clashRuntime.GroupSelections)
    Add-Detail ("Clash Runtime Alive/Dead   : {0}/{1} ({2})" -f $clashRuntime.AliveProxies, $clashRuntime.DeadProxies, $clashRuntime.AliveRatio)
    Add-Detail ("Clash Runtime Selected RTT : {0}" -f $clashRuntime.SelectedNodeLatency)
Add-Detail ("Clash Runtime Connections  : {0}" -f $clashRuntime.ActiveConnections)
Add-Detail ("Clash Runtime Throughput   : {0}" -f $clashRuntime.ThroughputTotal)
Add-Detail ("Clash Runtime Top Chains   : {0}" -f $clashRuntime.TopChains)
Add-Detail ("Clash Runtime DominantPath : {0}" -f $clashRuntime.DominantChain)
Add-Detail ("Clash Runtime DominantRate : {0}" -f $clashRuntime.DominantShare)
} elseif ($clashRuntime.Error -ne "<empty>") {
    Add-Detail ("Clash Runtime Error        : {0}" -f $clashRuntime.Error)
}
Add-Detail ("Network Path Mode          : {0}" -f $networkPathMode)
Add-Detail ("Network Path Tun           : {0}" -f $networkPathTun)
Add-Detail ("Network Path SystemProxy   : {0}" -f $networkPathSystemProxy)
Add-Detail ("Network Path Verdict       : {0}" -f $networkPathVerdict)

if ($localNetworkStatus -eq "OK" -or $localNetworkStatus -eq "PARTIAL") {
    Add-Diagnosis "本地网络基础可用，至少国内访问与默认路由证据成立。"
} else {
    Add-Diagnosis "未发现稳定的活动 IPv4 接口或默认网关，本地网络层可能就有问题。"
    Add-Suggestion "先确认网卡是否已连接，或切换网络后再复测。"
}
if ($dnsCn.OK) { Add-Diagnosis "国内 DNS 解析正常。" } else {
    Add-Diagnosis "国内 DNS 解析失败，可能是本机 DNS、网关 DNS 或网络本身异常。"
    Add-Suggestion "检查网卡 DNS 配置，必要时改成 223.5.5.5 或 119.29.29.29 后再测。"
}
if ($dnsGlobal.OK) { Add-Diagnosis "国外 DNS 解析成功。" } else {
    Add-Diagnosis "国外 DNS 解析失败或不稳定。"
    Add-Suggestion "若浏览器打不开国外网站，重点检查 Secure DNS、Clash DNS、TUN 或分流规则。"
}
if ($port7890.Listening) {
    Add-Diagnosis "代理端口正在监听，说明 Clash 或兼容代理进程大概率在运行。"
} else {
    Add-Diagnosis "代理端口未监听，浏览器和命令行即使配置代理也无法连上本地代理。"
    Add-Suggestion "确认 Clash 已启动，且本地 HTTP 代理端口确实是 7890。"
}
if ($httpGoogleProxy.OK -or $httpCloudflareProxy.OK) {
    Add-Diagnosis "通过本地代理访问国外站点成功，说明代理链路本身可用。"
} else {
    Add-Diagnosis "通过本地代理访问国外站点失败，问题可能在 Clash 节点、订阅、规则、上游网络或证书/TLS。"
    Add-Suggestion "检查 Clash 当前节点、订阅是否过期、规则模式以及节点日志。"
}
if (-not $httpGoogleDirect.OK -and ($httpGoogleProxy.OK -or $httpCloudflareProxy.OK)) {
    Add-Diagnosis "直连国外站点失败但代理成功，这是典型的“需要代理才能出海”场景。"
}
if ($curlTrace.Available) {
    if ($curlTrace.OK -and $curlTrace.ConnectedToProxy -and $curlTrace.TunnelEstablished -and $curlTrace.TLSOk) {
        Add-Diagnosis "curl 显示已连到本地代理、已建立 CONNECT 隧道、TLS 已完成，命令行代理链证据完整。"
    } elseif ($curlTrace.OK) {
        Add-Diagnosis "curl 显式指定 -x 后成功，但详细 CONNECT/TLS 证据不完整，仍可说明命令行代理链路基本可用。"
    } else {
        if ($httpGoogleProxy.OK -or $httpCloudflareProxy.OK) {
            Add-Diagnosis "curl 显式指定 -x 测试失败，但 PowerShell 代理请求成功，问题更像 curl 命令链路或目标站兼容性，而非 Clash 核心代理不可用。"
            Add-Suggestion "用 curl 测 cp.cloudflare.com/generate_204，并保留 -4、--proxy-http1.1 复测。"
        } else {
            Add-Diagnosis "curl 显式指定 -x 测试失败，且代理 HTTP 测试也失败，问题更偏向代理链路本身。"
        }
        Add-Suggestion "重点看 curl Verbose Trace 中 Trying、Connected、CONNECT、TLS 证据。"
    }
} else {
    Add-Diagnosis "未找到 curl.exe，无法补充命令行级别的真实代理链路证据。"
}
if ($routePrint.DefaultRoutes.Count -gt 1) {
    Add-Diagnosis "检测到多条默认路由，可能存在网卡优先级、虚拟网卡、VPN 或 TUN 抢路由情况。"
    Add-Suggestion "对比 route print 与 Get-NetRoute 的默认路由优先级，确认实际出接口。"
}
if ($proxyInfo.ProxyEnable -ne "1") {
    if ($proxyInfo.ProxyServer -ne "<empty>") {
        Add-Diagnosis "系统代理地址已写入，但开关未启用；浏览器若依赖系统代理，将不会自动走 Clash。"
    } else {
        Add-Diagnosis "系统代理未配置也未启用；浏览器若依赖系统代理，将不会自动走 Clash。"
    }
    Add-Suggestion "打开 Clash 的 System Proxy，或在浏览器/扩展里手动指定 127.0.0.1:7890。"
} else {
    Add-Diagnosis "系统代理已启用，但仍需确认浏览器没有被 PAC、扩展或独立设置覆盖。"
}
if ($browserHints.Chrome.HasSecureDns -or $browserHints.Edge.HasSecureDns) {
    Add-Diagnosis "至少有一个 Chromium 浏览器存在 Secure DNS 迹象，可能出现“代理没问题但浏览器 DNS 绕过”的情况。"
}
if ($browserHints.Chrome.HasExtensions -or $browserHints.Edge.HasExtensions) {
    Add-Diagnosis "至少有一个 Chromium 浏览器安装了扩展，代理扩展冲突值得排查。"
}
if ($winHttpStatus -eq "DIRECT" -and $proxyInfo.ProxyEnable -eq "1") {
    Add-Diagnosis "WinHTTP 仍是 Direct，而系统代理（WinINET）已开启；依赖 WinHTTP 的程序可能不走 Clash。"
    Add-Suggestion "若某应用只走 WinHTTP，可在管理员终端执行: netsh winhttp import proxy source=ie 后复测。"
}
if ($storeProbe.Verdict -eq "FAIL") {
    Add-Diagnosis "Microsoft Store 关键域名探测均失败，商店不可用更可能是网络/证书/系统服务层问题。"
    Add-Suggestion "优先检查 BITS、ClipSVC、InstallService、wuauserv 服务状态与系统时间。"
} elseif ($storeProbe.Verdict -eq "PARTIAL") {
    Add-Diagnosis ("Microsoft Store 部分异常（OK={0}, FAIL={1}），商店可能出现登录或下载异常。" -f $storeProbe.OKCount, $storeProbe.FailCount)
}
if (-not $wslProbe.Installed) {
    Add-Diagnosis "WSL 未安装，已跳过 WSL 网络探测。"
} elseif ($wslProbe.Verdict -eq "NO_DISTRO") {
    Add-Diagnosis "WSL 已安装但无发行版，无法执行 WSL 内 DNS/外网连通测试。"
} elseif ($wslProbe.Verdict -eq "WSL_ACCESS_DENIED") {
    Add-Diagnosis "WSL 状态读取被拒绝（E_ACCESSDENIED），当前进程权限或 WSL 服务状态异常。"
    Add-Suggestion "用管理员 PowerShell 执行 wsl --status 与 wsl -l -q，确认 LxssManager 服务正常。"
} elseif ($wslProbe.Verdict -eq "WSL_OK") {
    Add-Diagnosis ("WSL 正常：发行版={0}；模式={1}；镜像网络={2}；外网HTTPS={3}。" -f $wslProbe.Distros, $wslProbe.NetworkingMode, $wslProbe.MirrorMode, $wslProbe.Internet)
} elseif ($wslProbe.Verdict -eq "WSL_FAIL") {
    Add-Diagnosis ("WSL 异常：发行版={0}；模式={1}；镜像网络={2}；外网HTTPS={3}。" -f $wslProbe.Distros, $wslProbe.NetworkingMode, $wslProbe.MirrorMode, $wslProbe.Internet)
    Add-Suggestion "检查 WSL 网络模式（NAT/mirrored）与宿主机防火墙/VPN 冲突。"
} elseif ($wslProbe.Verdict -eq "WSL_PARTIAL") {
    Add-Diagnosis ("WSL 部分可用：发行版={0}；模式={1}；镜像网络={2}；DNS={3}；外网HTTPS={4}。" -f $wslProbe.Distros, $wslProbe.NetworkingMode, $wslProbe.MirrorMode, $wslProbe.Dns, $wslProbe.Internet)
    Add-Suggestion "若 DNS=OK 但外网HTTPS=FAIL，优先检查 WSL 出口路由、公司防火墙、代理与证书链策略。"
}
if (($wslProbe.NetworkingMode -replace '\s','').ToLowerInvariant() -eq "mirrored") {
    Add-Diagnosis "WSL 当前为 mirrored 镜像网络模式。"
} elseif (($wslProbe.NetworkingMode -replace '\s','').ToLowerInvariant() -eq "nat") {
    Add-Diagnosis "WSL 当前为 NAT 网络模式。"
}
if ($ncsiProbe.Verdict -eq "FAIL") {
    Add-Diagnosis "NCSI 探测失败，系统可能被判定为“无互联网”，影响商店/登录。"
    Add-Suggestion "检查 msftconnecttest 与 dns.msftncsi.com 是否被 DNS/防火墙拦截。"
} elseif ($ncsiProbe.Verdict -eq "PARTIAL") {
    Add-Diagnosis ("NCSI 部分异常：DNS={0} HTTP={1} Content={2}，可能导致系统组件误判离线。" -f $ncsiProbe.Dns, $ncsiProbe.Http, $ncsiProbe.Content)
}
if ($tlsProbe.Verdict -eq "TLS12_DISABLED") {
    Add-Diagnosis "系统 TLS1.2 客户端策略疑似被禁用，很多微软服务会失败。"
    Add-Suggestion "恢复 TLS1.2 客户端启用状态，并确认系统时间同步正常。"
} elseif ($tlsProbe.Verdict -eq "HANDSHAKE_OR_CERT_RISK") {
    Add-Diagnosis "TLS 探测失败，可能是证书链、系统时间或中间人拦截导致。"
}
if ($updateProbe.Verdict -eq "RISK") {
    Add-Diagnosis "Windows 更新依赖服务存在多项异常，商店与更新功能都可能受影响。"
    Add-Suggestion "优先修复 BITS/wuauserv/CryptSvc/UsoSvc/InstallService 状态。"
}
if ($fwProbe.Verdict -eq "FIREWALL_OFF") {
    Add-Diagnosis "Windows 防火墙三个配置文件均关闭，存在安全与网络策略不可控风险。"
}
if ($clashApi.Available) {
    Add-Diagnosis ("Clash API 可访问（探测端口 {0}），可以把 mode、TUN、端口等程序内部状态纳入证据链。" -f $apiProbePort)
    if ($clashRuntime.Available) {
        Add-Diagnosis ("Clash 运行态：存活节点 {0} / 失效节点 {1}（存活率 {2}）。" -f $clashRuntime.AliveProxies, $clashRuntime.DeadProxies, $clashRuntime.AliveRatio)
        if ($clashRuntime.GroupSelections -ne "<empty>") { Add-Diagnosis ("Clash 当前策略选择：{0}" -f $clashRuntime.GroupSelections) }
        if ($clashRuntime.ActiveConnections -ne "<empty>") { Add-Diagnosis ("Clash 当前活动连接数：{0}，链路分布：{1}" -f $clashRuntime.ActiveConnections, $clashRuntime.TopChains) }
        if ($clashRuntime.DominantChain -ne "<empty>") { Add-Diagnosis ("当前主要出口链路：{0}（占比 {1}）。" -f $clashRuntime.DominantChain, $clashRuntime.DominantShare) }
        if ($networkPathVerdict -ne "<empty>") { Add-Diagnosis ("当前网络路径判定：{0}。" -f $networkPathVerdict) }
        if ($clashApi.TunEnable -eq "True" -and $clashRuntime.DominantChain -eq "DIRECT") {
            Add-Diagnosis "TUN 已开启但主链路为 DIRECT，说明当前多数流量按规则直连，并非全量代理。"
        }
        if ($clashRuntime.AliveRatio -ne "<empty>") {
            try {
                $alivePct = [int]([double]$clashRuntime.AliveRatio.TrimEnd('%'))
                if ($alivePct -lt 40) { Add-Suggestion "可用节点比例偏低，建议在 Verge 内更新订阅并剔除失效节点后复测。" }
            } catch {}
        }
    }
} elseif ($clashApi.AuthRequired -or $apiAuthRequiredPorts.Count -gt 0) {
    Add-Diagnosis ("Clash API 端口已找到（探测端口 {0}），但需要访问密钥（401/403）。" -f $apiProbePort)
    Add-Suggestion "可用 -ClashSecret 传入当前密钥；脚本在成功后会加密保存，后续自动使用。"
} elseif ($apiAnyListening) {
    Add-Diagnosis ("检测到 API 相关端口监听（优先探测端口 {0}），但 Clash API 未成功读取，可能需要 secret 或 API 未完全开放。" -f $apiProbePort)
    Add-Suggestion "若你设置了 External Controller Secret，请用 -ClashSecret 参数重跑脚本。"
} else {
    Add-Diagnosis ("未检测到可用 Clash API 端口（已探测: {0}）。" -f (($candidateApiPorts | ForEach-Object { [string]$_ }) -join ", "))
    Add-Suggestion "在 Clash Verge 中确认已启用 External Controller，并核对端口（例如 9090 或 9097）。"
}

foreach ($r in $browserRisk) { Add-Suggestion $r }
Add-Suggestion "若浏览器仍异常，可先关闭浏览器 Secure DNS 后复测。"
Add-Suggestion "若某些网站转圈或偶发失败，可暂时关闭 QUIC / HTTP3 后复测。"
Add-Suggestion "用浏览器无痕模式复测，以排除扩展冲突。"
Add-Suggestion "若启用 TUN/VPN，结合 route print 默认路由和 198.18.0.0/15 证据判断是否真的接管流量。"
Add-Suggestion "若需要更深一层定位浏览器本体问题，可在浏览器启动参数中显式加代理或新建空白用户配置测试。"

Write-Section "总览摘要 / Summary"
foreach ($k in $script:Summary.Keys) {
    $value = $script:Summary[$k]
    $color = if ($value -in @("OK","ENABLED","LIKELY_OK","WSL_OK")) { "Green" } elseif ($value -in @("DISABLED","HIGH","MEDIUM","UNKNOWN","PARTIAL","UNAVAILABLE","AUTH_OR_API_ERROR","AUTH_REQUIRED","WSL_PARTIAL","WSL_ACCESS_DENIED","NO_WSL","NO_DISTRO","RISK","FIREWALL_OFF","PROXY_OR_AUTO","DIRECT","HANDSHAKE_OR_CERT_RISK","TLS12_DISABLED")) { "Yellow" } else { "Red" }
    Write-KeyValue -Key $k -Value $value -Color $color
}

Write-Section "状态速览 / Quick Status"
Write-StatusLine -Label "本地网络" -Ok ($localNetworkStatus -in @("OK","PARTIAL")) -Detail ("IPv4={0} / Gateway={1}" -f $(if ($nic) { $nic.IPv4 } else { "<empty>" }), $(if ($nic) { $nic.Gateway } else { "<empty>" }))
Write-StatusLine -Label "国内 DNS" -Ok $dnsCn.OK -Detail ("{0} via {1} in {2} ms" -f $dnsCn.IPs, $dnsCn.Server, $dnsCn.TimeMs)
Write-StatusLine -Label "国外 DNS" -Ok $dnsGlobal.OK -Detail ("{0} via {1} in {2} ms" -f $dnsGlobal.IPs, $dnsGlobal.Server, $dnsGlobal.TimeMs)
Write-StatusLine -Label ("代理端口 " + $ProxyPort) -Ok $port7890.Listening -Detail ("PID={0} Process={1}" -f $port7890.PID, $port7890.Process)
Write-StatusLine -Label "代理访问 Google" -Ok $httpGoogleProxy.OK -Detail ("status={0} via {1} in {2}s" -f $httpGoogleProxy.Status, $httpGoogleProxy.Proxy, $httpGoogleProxy.TimeSec)
Write-StatusLine -Label "curl 真实链路" -Ok ($curlTrace.Available -and $curlTrace.OK) -Detail ("proxy={0}; connect={1}; tls={2}" -f $(if ($curlTrace.ConnectedToProxy) { "YES" } else { "NO" }), $(if ($curlTrace.TunnelEstablished) { "YES" } else { "NO" }), $(if ($curlTrace.TLSOk) { "YES" } else { "NO" }))
Write-StatusLine -Label "系统代理" -Ok ($proxyInfo.ProxyEnable -eq "1") -Detail ("ProxyEnable={0} ProxyServer={1}" -f $proxyInfo.ProxyEnable, $proxyInfo.ProxyServer)
Write-StatusLine -Label "Clash API" -Ok $clashApi.Available -Detail ("Mode={0} Tun={1} Error={2}" -f $clashApi.Mode, $clashApi.TunEnable, $clashApi.Error)
Write-StatusLine -Label "WSL 外网(HTTPS)" -Ok ($wslProbe.Internet -eq "OK") -Detail ("MirrorMode={0}; Internet={1}" -f $wslProbe.MirrorMode, $wslProbe.Internet)

Write-Section "详细证据 / Details"
foreach ($d in $script:Details) {
    if ($d -eq "") { Write-Host "" } else { Write-Host $d -ForegroundColor Gray }
}

Write-Section "诊断解释 / Diagnosis"
$i = 1
foreach ($d in $script:Diagnosis) {
    Write-Host ("{0}. {1}" -f $i, $d) -ForegroundColor White
    $i++
}

Write-Section "建议动作 / Suggestions"
$i = 1
foreach ($s in $script:Suggestions) {
    Write-Host ("{0}. {1}" -f $i, $s) -ForegroundColor Yellow
    $i++
}

try {
    Save-Report -Path $reportFile
    Write-Host ""
    Write-Host ("报告已保存到: {0}" -f $reportFile) -ForegroundColor Green
} catch {
    Write-Host ""
    Write-Host ("报告保存失败: {0}" -f $_.Exception.Message) -ForegroundColor Red
}

Write-Host ""
Write-Host "脚本执行完毕。请按回车键退出窗口..." -ForegroundColor Cyan
Read-Host | Out-Null
