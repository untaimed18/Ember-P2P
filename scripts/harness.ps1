<#
.SYNOPSIS
    Local multi-node harness for Ember network development.

.DESCRIPTION
    Drives the EPX, friend rendezvous, QUIC punch, relay fallback, and
    Ember-native transport paths against a local rendezvous server,
    with each Ember client isolated via the EMBER_DATA_DIR override
    (config, identity, database, downloads, and logs all separate).

    Single-instance enforcement is skipped automatically by the app
    when EMBER_DATA_DIR is set, so multiple harness nodes can run
    side by side without colliding.

    Building is a separate step from launching: Windows holds an
    exclusive lock on a running ember.exe, so the script will refuse
    to rebuild while any node is still running. Run `build` once
    before any nodes, and rerun it whenever Rust or frontend code
    changes.

.PARAMETER Command
    rendezvous   Build (release) and run the local rendezvous server.
    build        Build the Ember client (release, with the harness
                 cargo feature so devtools are available).
    node         Run an isolated Ember client. Build must already
                 have produced ember.exe; rerun `build` if you have
                 changed Rust or frontend code.
    reset        Delete the harness data directories.

.PARAMETER Node
    Node identifier when Command is "node" (e.g. a, b, c).

.PARAMETER TcpPort
    TCP port for the node's eD2K listener. Defaults are 4662 / 4762 / 4862
    for nodes a / b / c.

.PARAMETER UdpPort
    UDP port for the node's KAD listener. Defaults are 4672 / 4772 / 4872.

.PARAMETER RendezvousPort
    Port for the local rendezvous server (default 8080).

.EXAMPLE
    .\scripts\harness.ps1 rendezvous

.EXAMPLE
    .\scripts\harness.ps1 build
    .\scripts\harness.ps1 node -Node a
    .\scripts\harness.ps1 node -Node b

.EXAMPLE
    .\scripts\harness.ps1 reset
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('rendezvous', 'build', 'node', 'reset')]
    [string]$Command,

    [Parameter()]
    [string]$Node,

    [Parameter()]
    [int]$TcpPort,

    [Parameter()]
    [int]$UdpPort,

    [Parameter()]
    [int]$RendezvousPort = 8080
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$HarnessRoot = Join-Path $RepoRoot '.harness'
$EmberExe = Join-Path $RepoRoot 'src-tauri/target/release/ember.exe'

function Get-NodeDefaults {
    param([string]$NodeId)

    switch ($NodeId.ToLower()) {
        'a' { return @{ Tcp = 4662; Udp = 4672 } }
        'b' { return @{ Tcp = 4762; Udp = 4772 } }
        'c' { return @{ Tcp = 4862; Udp = 4872 } }
        default { return @{ Tcp = $null; Udp = $null } }
    }
}

function Test-EmberExeIsLocked {
    if (-not (Test-Path $EmberExe)) { return $false }
    try {
        # Windows enforces an exclusive write-share on a running PE
        # image. Opening for write briefly is the only reliable way to
        # tell from PowerShell whether the binary is currently in use
        # by another process.
        $stream = [System.IO.File]::Open($EmberExe, 'Open', 'Write', 'None')
        $stream.Close()
        return $false
    } catch {
        return $true
    }
}

function Invoke-Rendezvous {
    $serverDir = Join-Path $RepoRoot 'rendezvous-server'
    if (-not (Test-Path $serverDir)) {
        throw "Cannot find rendezvous-server at $serverDir"
    }

    $env:PORT = "$RendezvousPort"
    if (-not $env:RUST_LOG) { $env:RUST_LOG = 'ember_rendezvous=debug' }

    Write-Host "Starting rendezvous server on 0.0.0.0:$RendezvousPort" -ForegroundColor Cyan
    Push-Location $serverDir
    try {
        & cargo run --release
    } finally {
        Pop-Location
    }
}

function Invoke-Build {
    if (Test-EmberExeIsLocked) {
        throw "$EmberExe is currently in use by a running Ember process. " +
              "Close every harness node window (and any other ember.exe), then rerun 'build'."
    }

    Write-Host "Building Ember client (release, --features harness)..." -ForegroundColor Cyan
    Push-Location $RepoRoot
    try {
        & npm run tauri build -- --features harness --no-bundle
        if ($LASTEXITCODE -ne 0) { throw "tauri build failed (exit $LASTEXITCODE)" }
    } finally {
        Pop-Location
    }

    if (-not (Test-Path $EmberExe)) {
        throw "Build reported success but ember.exe was not produced at $EmberExe"
    }

    Write-Host "Built $EmberExe" -ForegroundColor Green
    Write-Host "Now launch nodes with: .\scripts\harness.ps1 node -Node a" -ForegroundColor DarkGray
}

function Invoke-Node {
    if ([string]::IsNullOrWhiteSpace($Node)) {
        throw "node command requires -Node <id> (e.g. -Node a)"
    }

    if (-not (Test-Path $EmberExe)) {
        throw "ember.exe not found at $EmberExe. Run '.\scripts\harness.ps1 build' first."
    }

    $defaults = Get-NodeDefaults -NodeId $Node
    if (-not $TcpPort) { $TcpPort = $defaults.Tcp }
    if (-not $UdpPort) { $UdpPort = $defaults.Udp }
    if (-not $TcpPort -or -not $UdpPort) {
        throw "Unknown node id '$Node'. Pass -TcpPort and -UdpPort explicitly, or use one of: a, b, c."
    }

    $dataDir = Join-Path $HarnessRoot ("node-{0}" -f $Node.ToLower())
    New-Item -ItemType Directory -Path $dataDir -Force | Out-Null

    # Pre-seed config.json so the node starts on the harness rendezvous
    # URL with non-conflicting ports. AppConfig::load merges this with
    # defaults on first launch, and treats setup_complete=true as
    # "skip the wizard" so the run is fully unattended. The Ember-native
    # transport flag is force-set every launch so a node that was first
    # created before that field existed will pick it up next time —
    # otherwise `AppSettings`'s `#[serde(default)] = false` would leave
    # `ember_ping_peer` returning "Ember-native transport is disabled".
    $configPath = Join-Path $dataDir 'config.json'
    $rendezvousUrl = "http://127.0.0.1:$RendezvousPort"

    $existing = @{}
    if (Test-Path $configPath) {
        try {
            $raw = Get-Content -Raw -Path $configPath
            if ($raw) {
                $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
                # Convert PSCustomObject → hashtable so we can index by key.
                foreach ($prop in $parsed.PSObject.Properties) {
                    $existing[$prop.Name] = $prop.Value
                }
            }
        } catch {
            Write-Host "Existing $configPath could not be parsed ($_); replacing it." -ForegroundColor Yellow
            $existing = @{}
        }
    }

    # Force-applied harness keys. Anything else the app previously
    # wrote (download_folder, shared_folders, identity-adjacent
    # settings) is preserved.
    $existing['tcp_port']             = $TcpPort
    $existing['udp_port']             = $UdpPort
    $existing['rendezvous_url']       = $rendezvousUrl
    $existing['auto_connect_kad']     = $false
    $existing['setup_complete']       = $true
    $existing['ember_native_enabled'] = $true

    $merged = $existing | ConvertTo-Json -Depth 8
    Set-Content -Path $configPath -Value $merged -NoNewline
    Write-Host "Wrote harness keys to $configPath" -ForegroundColor DarkCyan

    $env:EMBER_DATA_DIR = $dataDir
    Write-Host "Launching Ember node '$Node' (tcp=$TcpPort udp=$UdpPort)" -ForegroundColor Cyan
    Write-Host "  EMBER_DATA_DIR=$dataDir" -ForegroundColor DarkGray
    Write-Host "  Press Ctrl+Shift+I in the window to open devtools." -ForegroundColor DarkGray
    Write-Host "  await window.__TAURI__.core.invoke('get_ember_diagnostics')" -ForegroundColor DarkGray

    & $EmberExe
}

function Invoke-Reset {
    if (Test-Path $HarnessRoot) {
        Write-Host "Removing $HarnessRoot" -ForegroundColor Yellow
        Remove-Item -Recurse -Force $HarnessRoot
    } else {
        Write-Host "No harness data to reset (.harness does not exist)" -ForegroundColor Yellow
    }
}

switch ($Command) {
    'rendezvous' { Invoke-Rendezvous }
    'build'      { Invoke-Build }
    'node'       { Invoke-Node }
    'reset'      { Invoke-Reset }
}
