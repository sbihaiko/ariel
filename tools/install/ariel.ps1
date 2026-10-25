<#
  Ariel's installer for Windows: make the keys, build the payload with them,
  send it to the console, and leave the token where the next command can read
  it. PowerShell speaks the socket itself, so no nc is needed.

    .\ariel.ps1 -ConsoleHost 192.168.1.50        install and send
    .\ariel.ps1 -ConsoleHost 192.168.1.50 -Check  say what would happen, change nothing
    .\ariel.ps1 -Sign                            sign one challenge line on stdin

  The payload pins the owner's own two keys, which is why a published build is
  useless: this builds one that approves on this owner's console. The build
  runs in Docker, so no C toolchain is needed here; Docker Desktop must be
  running. Nothing here deploys through `make test`, and nothing changes the
  gate.

  Environment: ARIEL_KEY_DIR (default %USERPROFILE%\.config\ariel),
  ARIEL_SDK_IMAGE (default ariel-ps5-sdk).
#>

param(
    [string]$ConsoleHost,
    [switch]$Check,
    [switch]$Sign
)

$ErrorActionPreference = "Stop"
$Root = (Resolve-Path "$PSScriptRoot\..\..").Path
$KeyDir = if ($env:ARIEL_KEY_DIR) { $env:ARIEL_KEY_DIR } else { Join-Path $env:USERPROFILE ".config\ariel" }
$Image = if ($env:ARIEL_SDK_IMAGE) { $env:ARIEL_SDK_IMAGE } else { "ariel-ps5-sdk" }
$LoaderPort = 9021
$AgentPort = 2324
$FtpPort = 2121
$Payload = Join-Path $Root "ariel-ps5.elf"

function Say($Message) { Write-Host $Message }
function Die($Message) { Write-Error "ariel: $Message"; exit 1 }

function Test-Port([string]$Machine, [int]$Port, [int]$TimeoutMs = 2000) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $task = $client.ConnectAsync($Machine, $Port)
        if (-not $task.Wait($TimeoutMs)) { return $false }
        return $client.Connected
    } catch { return $false } finally { $client.Close() }
}

function Invoke-Docker([string[]]$Arguments) {
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) { Die "docker failed" }
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Die "Docker Desktop is needed for the build; install it and run this again"
}

# The signer is a portable C build, and on Windows it runs where its toolchain
# is: inside the container. The keys it writes are plain hex files, so they are
# the same on every machine.
function Invoke-Signer([string[]]$SignerArguments) {
    $mount = "$($KeyDir):/keys"
    Invoke-Docker @(
        "run", "--rm", "-i", "-v", "$($Root):/src", "-v", $mount, "-w", "/src",
        $Image, "sh", "-lc",
        "make -s -C hostbuild ariel-sign >/dev/null && ./hostbuild/ariel-sign $($SignerArguments -join ' ')"
    )
}

if ($Sign) {
    $challenge = [Console]::In.ReadLine()
    if (-not $challenge) { Die "no challenge on standard input" }
    $challenge | & docker run --rm -i -v "$($Root):/src" -v "$($KeyDir):/keys" -w /src $Image `
        sh -lc "make -s -C hostbuild ariel-sign >/dev/null && ./hostbuild/ariel-sign sign /keys/owner.key"
    exit $LASTEXITCODE
}

if (-not $ConsoleHost) { $ConsoleHost = Read-Host "the console's address" }
if (-not $ConsoleHost) { Die "usage: ariel.ps1 -ConsoleHost <address>" }

Say "console: $ConsoleHost"
if (-not (Test-Port $ConsoleHost $LoaderPort)) {
    Die "nothing answers on $($ConsoleHost):$LoaderPort -- start elfldr on the console first"
}
Say "  the loader answers on $LoaderPort"

if (-not (Test-Path $KeyDir)) { New-Item -ItemType Directory -Path $KeyDir | Out-Null }

Say "building the SDK image if it is not here yet (first run takes some minutes)"
Invoke-Docker @("build", "-q", "-t", $Image, "-f", "$($Root)\tools\install\Dockerfile.sdk", $Root) | Out-Null

$keyScript = 'for n in owner recovery; do [ -f /keys/$n.key ] || ./hostbuild/ariel-sign keygen /keys/$n.key; done; ' +
             './hostbuild/ariel-sign pubkey /keys/owner.key; ./hostbuild/ariel-sign pubkey /keys/recovery.key'
$keys = & docker run --rm -v "$($Root):/src" -v "$($KeyDir):/keys" -w /src $Image sh -lc $keyScript
if ($LASTEXITCODE -ne 0) { Die "cannot make the keys" }
$owner = $keys[0].Trim()
$recovery = $keys[-1].Trim()
if ($owner -eq $recovery) { Die "the owner and the recovery key are the same; remove one and run again" }
Say "  owner key:    $owner"
Say "  recovery key: $recovery"

if ($Check) {
    Say "check: the console answers, the keys are in $KeyDir, and the build would pin them"
    exit 0
}

Say "building the payload in the container"
Invoke-Docker @(
    "run", "--rm", "-v", "$($Root):/src", "-w", "/src",
    "-e", "ARIEL_PUBKEY=$owner", "-e", "ARIEL_RECOVERY_PUBKEY=$recovery",
    $Image, "make"
) | Out-Null
if (-not (Test-Path $Payload)) { Die "the build wrote no $Payload" }

Say "sending $Payload to $($ConsoleHost):$LoaderPort"
$bytes = [System.IO.File]::ReadAllBytes($Payload)
$client = New-Object System.Net.Sockets.TcpClient($ConsoleHost, $LoaderPort)
try {
    $stream = $client.GetStream()
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush()
} finally { $client.Close() }

$waited = 0
while ($waited -lt 60 -and -not (Test-Port $ConsoleHost $AgentPort)) {
    Start-Sleep -Seconds 2
    $waited += 2
}
if (-not (Test-Port $ConsoleHost $AgentPort)) {
    Die "the payload never opened $AgentPort -- read the console's log"
}
Say "  the agent port answers on $AgentPort"

$token = ""
if (Test-Port $ConsoleHost $FtpPort) {
    try {
        $request = [System.Net.FtpWebRequest]::Create("ftp://$($ConsoleHost):$FtpPort/data/ariel/token")
        $request.Method = [System.Net.WebRequestMethods+Ftp]::DownloadFile
        $response = $request.GetResponse()
        $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
        $token = $reader.ReadToEnd().Trim()
        $reader.Close(); $response.Close()
    } catch { $token = "" }
}
if ($token -notmatch '^[0-9a-f]{32}$') {
    $token = ""
    Say "The token is on the console's screen and in /data/ariel/token."
    $token = (Read-Host "token").Trim()
}
if ($token -notmatch '^[0-9a-f]{32}$') { Say "warning: that token is not 32 hex characters" }

$envFile = Join-Path $Root "ariel.env"
"PS5_HOST=$ConsoleHost`nARIEL_TOKEN=$token" | Set-Content -Path $envFile -Encoding ascii
Say "wrote $envFile"

Say ""
Say "Ariel is running. From here:"
Say "  `$env:PS5_HOST = '$ConsoleHost'"
Say "  `$env:ARIEL_TOKEN = '$token'"
Say "The rest is docs\quick-start.md."
