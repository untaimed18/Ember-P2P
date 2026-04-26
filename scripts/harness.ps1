<#
.SYNOPSIS
    Local multi-node harness for Ember network development.

.DESCRIPTION
    Drives the EPX, friend rendezvous, QUIC punch, and relay fallback
    paths against a local rendezvous server, with each Ember client
    isolated via the EMBER_DATA_DIR override (config, identity,
    database, downloads, and logs all separate).

    Single-instance enforcement is skipped automatically by the app
    when EMBER_DATA_DIR is set, so multiple harness nodes can run
    side by side without colliding.

.PARAMETER Command
    rendezvous   Build (release) and run the local rendezvous server.
    node         Build (release) and run an isolated Ember client.
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
    .\scripts\harness.ps1 node -Node a

.EXAMPLE
    .\scripts\harness.ps1 reset
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('rendezvous', 'node', 'reset')]
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

function Get-NodeDefaults {
    param([string]$NodeId)

    switch ($NodeId.ToLower()) {
        'a' { return @{ Tcp = 4662; Udp = 4672 } }
        'b' { return @{ Tcp = 4762; Udp = 4772 } }
        'c' { return @{ Tcp = 4862; Udp = 4872 } }
        default { return @{ Tcp = $null; Udp = $null } }
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

function Invoke-Node {
    if ([string]::IsNullOrWhiteSpace($Node)) {
        throw "node command requires -Node <id> (e.g. -Node a)"
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
    # transport flag is seeded on so `ember_ping_peer` works without
    # any post-launch settings edit; toggling it off via the in-app
    # settings still works.
    $configPath = Join-Path $dataDir 'config.json'
    if (-not (Test-Path $configPath)) {
        $rendezvousUrl = "http://127.0.0.1:$RendezvousPort"
        $seed = @{
            tcp_port             = $TcpPort
            udp_port             = $UdpPort
            rendezvous_url       = $rendezvousUrl
            auto_connect_kad     = $false
            setup_complete       = $true
            ember_native_enabled = $true
        } | ConvertTo-Json -Depth 4
        Set-Content -Path $configPath -Value $seed -NoNewline
        Write-Host "Seeded $configPath" -ForegroundColor DarkCyan
    }

    $env:EMBER_DATA_DIR = $dataDir
    Write-Host "Launching Ember node '$Node' (tcp=$TcpPort udp=$UdpPort) with EMBER_DATA_DIR=$dataDir" -ForegroundColor Cyan
    Write-Host "  • Press Ctrl+Shift+I in the window to open devtools." -ForegroundColor DarkGray
    Write-Host "  • Use window.__TAURI__.core.invoke('get_ember_diagnostics') to read the local pubkey." -ForegroundColor DarkGray

    Push-Location $RepoRoot
    try {
        & npm run tauri build -- --features harness --no-bundle
        if ($LASTEXITCODE -ne 0) { throw "tauri build failed (exit $LASTEXITCODE)" }

        $exe = Join-Path $RepoRoot 'src-tauri/target/release/ember.exe'
        if (-not (Test-Path $exe)) {
            throw "Built ember.exe not found at $exe"
        }
        & $exe
    } finally {
        Pop-Location
    }
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
    'node'       { Invoke-Node }
    'reset'      { Invoke-Reset }
}
