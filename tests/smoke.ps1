param(
    [string]$PackageDir = (Join-Path $PSScriptRoot '..\package')
)

$ErrorActionPreference = 'Stop'
$PackageDir = (Resolve-Path -LiteralPath $PackageDir).Path
$serverExe = Join-Path $PackageDir 'server.exe'
$clientExe = Join-Path $PackageDir 'client.exe'
$xrayExe = Join-Path $PackageDir 'xray.exe'
foreach ($exe in @($serverExe, $clientExe, $xrayExe)) {
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "Missing executable: $exe" }
}
$previousXrayBin = $env:XRAY_BIN
$env:XRAY_BIN = $xrayExe
$tempDir = Join-Path ([IO.Path]::GetTempPath()) ('rustproxy-smoke-' + [guid]::NewGuid().ToString('N'))
$processes = [Collections.Generic.List[System.Diagnostics.Process]]::new()
$ports = [Collections.Generic.HashSet[int]]::new()

function Get-FreePort {
    do {
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        $listener.Start()
        try { $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port } finally { $listener.Stop() }
    } while (-not $ports.Add($port))
    return $port
}

function Wait-Listening([int]$port, [System.Diagnostics.Process]$process) {
    $deadline = [DateTime]::UtcNow.AddSeconds(20)
    while ([DateTime]::UtcNow -lt $deadline) {
        $process.Refresh()
        if ($process.HasExited) { throw "Process exited before port $port became ready (exit $($process.ExitCode))" }
        $socket = [Net.Sockets.TcpClient]::new()
        try {
            $pending = $socket.ConnectAsync('127.0.0.1', $port)
            if ($pending.Wait(250) -and $socket.Connected) { return }
        } catch { } finally { $socket.Dispose() }
        Start-Sleep -Milliseconds 100
    }
    throw "Timed out waiting for local port $port"
}

function Start-Wrapper([string]$exe, [string]$config, [string]$label) {
    $p = Start-Process -FilePath $exe -ArgumentList @('run', ('"' + $config + '"')) -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $tempDir "$label.out") -RedirectStandardError (Join-Path $tempDir "$label.err")
    $processes.Add($p)
    return $p
}

try {
    New-Item -ItemType Directory -Path $tempDir | Out-Null
    $setupDir = Join-Path $tempDir 'generated'
    & $serverExe setup $setupDir '127.0.0.1' 'www.microsoft.com' 'www.microsoft.com:443' '127.0.0.1'
    if ($LASTEXITCODE -ne 0) { throw 'Server setup failed' }
    $generatedServer = Get-Content (Join-Path $setupDir 'server_config.json') -Raw | ConvertFrom-Json
    $generatedClient = Get-Content (Join-Path $setupDir 'client_config.json') -Raw | ConvertFrom-Json
    if ($generatedServer.port -lt 1 -or $generatedServer.port -ne $generatedClient.server_port -or $generatedClient.PSObject.Properties.Name -contains 'private_key') { throw 'Generated profiles are invalid' }
    $imported = Join-Path $tempDir 'imported.json'
    & $clientExe import-auto (Join-Path $setupDir 'client_config.json') $imported
    if ($LASTEXITCODE -ne 0) { throw 'Client import failed' }
    & $clientExe check $imported
    if ($LASTEXITCODE -ne 0) { throw 'Imported profile failed Xray validation' }
    & $clientExe import-auto (Join-Path $setupDir 'client_config.json') $imported 2>$null
    if ($LASTEXITCODE -eq 0) { throw 'Import unexpectedly overwrote an existing profile' }
    $generated = (& $xrayExe x25519 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw 'Xray key generation failed' }
    if ($generated -notmatch '(?m)^PrivateKey:\s*(\S+)') { throw 'Unexpected Xray private key output' }
    $privateKey = $Matches[1]
    if ($generated -notmatch '(?m)^(?:Password \(PublicKey\)|PublicKey):\s*(\S+)') { throw 'Unexpected Xray public key output' }
    $publicKey = $Matches[1]
    $uuid = [guid]::NewGuid().ToString()
    $badUuid = [guid]::NewGuid().ToString()
    $shortBytes = [byte[]]::new(8)
    [Security.Cryptography.RandomNumberGenerator]::Fill($shortBytes)
    $shortId = [Convert]::ToHexString($shortBytes).ToLowerInvariant()
    $serverPort = Get-FreePort
    $socksPort = Get-FreePort
    $httpPort = Get-FreePort
    $badSocksPort = Get-FreePort
    $badHttpPort = Get-FreePort
    $serverConfig = Join-Path $tempDir 'server.json'
    $clientConfig = Join-Path $tempDir 'client.json'
    $badConfig = Join-Path $tempDir 'bad-client.json'
    $server = @{
        listen = '127.0.0.1'; port = $serverPort; clients = @($uuid)
        dest = 'www.microsoft.com:443'; server_names = @('www.microsoft.com')
        private_key = $privateKey; short_ids = @($shortId)
    }
    $client = @{
        server_address = '127.0.0.1'; server_port = $serverPort; uuid = $uuid
        public_key = $publicKey; short_id = $shortId; server_name = 'www.microsoft.com'
        socks_port = $socksPort; http_port = $httpPort
    }
    $server | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $serverConfig -Encoding utf8NoBOM
    $client | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $clientConfig -Encoding utf8NoBOM
    $client.uuid = $badUuid; $client.socks_port = $badSocksPort; $client.http_port = $badHttpPort
    $client | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $badConfig -Encoding utf8NoBOM

    & $clientExe check $clientConfig
    if ($LASTEXITCODE -ne 0) { throw 'Client configuration check failed' }
    $serverProcess = Start-Wrapper $serverExe $serverConfig 'server'
    Wait-Listening $serverPort $serverProcess
    & $clientExe tcp-ping $clientConfig
    if ($LASTEXITCODE -ne 0) { throw 'TCP ping failed' }
    $clientProcess = Start-Wrapper $clientExe $clientConfig 'client'
    Wait-Listening $httpPort $clientProcess
    Write-Host 'Testing an HTTPS request through the HTTP proxy (requires outbound Microsoft connectivity).'
    & curl.exe --silent --show-error --fail --max-time 30 --noproxy '' --proxy "http://127.0.0.1:$httpPort" --output NUL 'https://www.microsoft.com/'
    if ($LASTEXITCODE -ne 0) { throw 'HTTPS proxy request failed; check outbound DNS, firewall, Microsoft reachability and TLS policy on this runner.' }

    $badProcess = Start-Wrapper $clientExe $badConfig 'bad-client'
    Wait-Listening $badHttpPort $badProcess
    & curl.exe --silent --max-time 15 --noproxy '' --proxy "http://127.0.0.1:$badHttpPort" --output NUL 'https://www.microsoft.com/'
    if ($LASTEXITCODE -eq 0) { throw 'Invalid UUID unexpectedly succeeded' }
    Write-Host 'Smoke test passed: configuration, TCP ping, HTTPS proxy, and invalid UUID rejection.'
} finally {
    foreach ($process in $processes) {
        $process.Refresh()
        if (-not $process.HasExited) {
            & taskkill.exe /PID $process.Id /T /F 2>$null | Out-Null
            $process.WaitForExit(5000) | Out-Null
        }
        $process.Dispose()
    }
    if (Test-Path -LiteralPath $tempDir) { Remove-Item -LiteralPath $tempDir -Recurse -Force }
    if ($null -eq $previousXrayBin) { Remove-Item Env:XRAY_BIN -ErrorAction SilentlyContinue }
    else { $env:XRAY_BIN = $previousXrayBin }
}
