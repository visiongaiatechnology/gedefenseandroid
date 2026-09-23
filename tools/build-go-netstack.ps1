# STATUS: DIAMANT VGT SUPREME
# Reproducibly builds the process-isolated GaiaNet V2 helper artifacts.
# GaiaNet source remains Go-only. arm64 links internally; Go requires an Android NDK external
# linker for android/amd64, so x86_64 uses the pinned NDK toolchain without adding runtime JNI code.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Netstack = Join-Path $Root 'netstack'
$JniRoot = Join-Path $Root 'app\src\main\jniLibs'

function Fail([string]$Message) {
    Write-Error $Message
    exit 1
}

$Go = Get-Command go.exe -ErrorAction SilentlyContinue
if ($null -eq $Go) { $Go = Get-Command go -ErrorAction SilentlyContinue }
if ($null -eq $Go) { Fail 'Go was not found. GeDefense Mobile requires Go 1.26.8 to build GaiaNet V2.' }
$GoVersion = (& $Go.Source version | Out-String).Trim()
if ($GoVersion -notmatch '\bgo1\.26\.8(?:\s|$)') {
    Fail "Unreviewed Go toolchain: $GoVersion. Expected Go 1.26.8."
}

$PriorEnv = @{}
foreach ($Name in @('GOTOOLCHAIN','GOFLAGS','GOPROXY','GOSUMDB','GOOS','GOARCH','CGO_ENABLED','CC','CXX')) {
    $PriorEnv[$Name] = [Environment]::GetEnvironmentVariable($Name, 'Process')
}

function Restore-Environment {
    foreach ($Name in $PriorEnv.Keys) {
        $Value = $PriorEnv[$Name]
        if ($null -eq $Value) {
            Remove-Item "Env:$Name" -ErrorAction SilentlyContinue
        } else {
            [Environment]::SetEnvironmentVariable($Name, $Value, 'Process')
        }
    }
}

Push-Location $Netstack
try {
    Write-Host '[GaiaNet V2 1/4] Module integrity + static/race gates'
    $env:GOTOOLCHAIN = 'local'
    $env:GOFLAGS = '-mod=readonly'
    $env:GOPROXY = 'off'
    $env:GOSUMDB = 'off'
    $env:CGO_ENABLED = '0'
    Remove-Item Env:CC -ErrorAction SilentlyContinue
    Remove-Item Env:CXX -ErrorAction SilentlyContinue

    & $Go.Source mod verify
    if ($LASTEXITCODE -ne 0) { Fail 'Go module verification failed.' }
    $ModuleList = (& $Go.Source list -m all | Out-String).Trim().Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries)
    $ExpectedModules = @(
        'visiongaia.dev/gedefense/mobile/netstack',
        'golang.org/x/crypto v0.37.0 => ../third_party/go/x-crypto',
        'golang.org/x/net v0.39.0 => ../third_party/go/x-net',
        'golang.org/x/sys v0.32.0 => ../third_party/go/x-sys',
        'golang.org/x/term v0.31.0 => ../third_party/go/x-term',
        'golang.org/x/text v0.24.0 => ../third_party/go/x-text',
        'golang.zx2c4.com/wireguard v0.0.20250522 => ../third_party/go/wireguard-go'
    )
    if ($ModuleList.Count -ne $ExpectedModules.Count) {
        Fail "Unreviewed Go module dependency count: $($ModuleList.Count)."
    }
    foreach ($Expected in $ExpectedModules) {
        if ($ModuleList -notcontains $Expected) { Fail "Go module graph mismatch: $Expected" }
    }
    & $Go.Source test ./...
    if ($LASTEXITCODE -ne 0) { Fail 'GaiaNet unit tests failed.' }
    & $Go.Source vet ./...
    if ($LASTEXITCODE -ne 0) { Fail 'GaiaNet go vet failed.' }
    & $Go.Source test -race ./...
    if ($LASTEXITCODE -ne 0) { Fail 'GaiaNet race detector failed.' }
    & $Go.Source test -tags=gdandroidhelper ./...
    if ($LASTEXITCODE -ne 0) { Fail 'GaiaNet helper protocol tests failed.' }
    & $Go.Source vet -tags=gdandroidhelper ./...
    if ($LASTEXITCODE -ne 0) { Fail 'GaiaNet helper-tag go vet failed.' }

    Write-Host '[GaiaNet V2 2/4] Build arm64-v8a pure-Go Android helper'
    $ArmDir = Join-Path $JniRoot 'arm64-v8a'
    New-Item -ItemType Directory -Force -Path $ArmDir | Out-Null
    $env:GOOS = 'android'
    $env:GOARCH = 'arm64'
    $env:CGO_ENABLED = '0'
    $ArmHelper = Join-Path $ArmDir 'libgedefense_gaianet_v2.so'
    & $Go.Source build -trimpath -buildvcs=false -ldflags='-s -w -buildid= -R 0x4000' -o $ArmHelper .
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $ArmHelper -PathType Leaf)) { Fail 'arm64-v8a GaiaNet V2 build failed.' }

    Write-Host '[GaiaNet V2 3/4] Build x86_64 Android helper with pinned NDK linker'
    $X64Dir = Join-Path $JniRoot 'x86_64'
    New-Item -ItemType Directory -Force -Path $X64Dir | Out-Null
    # Go 1.26.8 requires external/cgo linking for android/amd64. Use only the pinned
    # Android NDK linker; GaiaNet itself contains no cgo/JNI transport logic.
    $SdkRoot = if ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT } elseif ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { $null }
    if ([string]::IsNullOrWhiteSpace($SdkRoot)) { Fail 'ANDROID_SDK_ROOT/ANDROID_HOME is required for the x86_64 Android helper.' }
    $NdkRoot = Join-Path $SdkRoot 'ndk\27.2.12479018'
    $NdkBin = Join-Path $NdkRoot 'toolchains\llvm\prebuilt\windows-x86_64\bin'
    $X64Clang = Join-Path $NdkBin 'x86_64-linux-android29-clang.cmd'
    $X64ClangXX = Join-Path $NdkBin 'x86_64-linux-android29-clang++.cmd'
    if (-not (Test-Path -LiteralPath $X64Clang -PathType Leaf)) { Fail "Pinned Android NDK x86_64 clang missing: $X64Clang" }
    if (-not (Test-Path -LiteralPath $X64ClangXX -PathType Leaf)) { Fail "Pinned Android NDK x86_64 clang++ missing: $X64ClangXX" }
    $env:GOOS = 'android'
    $env:GOARCH = 'amd64'
    $env:CGO_ENABLED = '1'
    $env:CC = (Resolve-Path -LiteralPath $X64Clang).Path
    $env:CXX = (Resolve-Path -LiteralPath $X64ClangXX).Path
    $X64Helper = Join-Path $X64Dir 'libgedefense_gaianet_v2.so'
    & $Go.Source build -trimpath -buildvcs=false -ldflags='-s -w -buildid= -extldflags=-Wl,-z,max-page-size=16384' -o $X64Helper .
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $X64Helper -PathType Leaf)) { Fail 'x86_64 GaiaNet V2 Android build failed.' }

    Write-Host '[GaiaNet V2 4/4] Artifact sanity'
    foreach ($Artifact in @($ArmHelper,$X64Helper)) {
        $Bytes = [IO.File]::ReadAllBytes($Artifact)
        if ($Bytes.Length -lt 4 -or $Bytes[0] -ne 0x7f -or $Bytes[1] -ne 0x45 -or $Bytes[2] -ne 0x4c -or $Bytes[3] -ne 0x46) {
            Fail "GaiaNet helper is not ELF: $Artifact"
        }
        $Hash = Get-FileHash -LiteralPath $Artifact -Algorithm SHA256
        Write-Host "$Artifact SHA-256=$($Hash.Hash.ToLowerInvariant())"
    }
} finally {
    Restore-Environment
    Pop-Location
}

Write-Host 'GAIANET_V2_BUILD_PASS'
