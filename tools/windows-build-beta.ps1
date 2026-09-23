# STATUS: DIAMANT VGT SUPREME
# Controlled beta build: source gates -> reproducible GaiaNet V2 helpers -> Android build -> lint -> APK audit/hash.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $Root

function Fail([string]$Message) {
    Write-Error $Message
    exit 1
}

$Gradle = Get-Command gradle.bat -ErrorAction SilentlyContinue
if ($null -eq $Gradle) { $Gradle = Get-Command gradle -ErrorAction SilentlyContinue }
if ($null -eq $Gradle) { Fail 'Gradle was not found. Install/verify Gradle 8.7 or use Android Studio with trusted Gradle 8.7.' }
$VersionOutput = (& $Gradle.Source --version | Out-String)
if ($LASTEXITCODE -ne 0 -or $VersionOutput -notmatch '(?m)^Gradle 8\.7\s*$') {
    Fail 'This release is pinned to Gradle 8.7. Refusing an unreviewed Gradle version.'
}
$JavaVersion = (& java -version 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0 -or $JavaVersion -notmatch 'version "17[\._]') { Fail 'JDK 17 is mandatory for the controlled beta build.' }

Write-Host '[1/5] Source/security gates'
python tools/verify-source-manifest.py
if ($LASTEXITCODE -ne 0) { Fail 'Source manifest verification failed.' }
$Bash = Get-Command bash.exe -ErrorAction SilentlyContinue
if ($null -eq $Bash) { $Bash = Get-Command bash -ErrorAction SilentlyContinue }
if ($null -eq $Bash) {
    $GitBash = 'C:\Program Files\Git\bin\bash.exe'
    if (Test-Path -LiteralPath $GitBash -PathType Leaf) { $Bash = Get-Item $GitBash }
}
if ($null -eq $Bash) { Fail 'Controlled beta build requires Bash/Git Bash for the mandatory security audit.' }
$BashPath = if ($Bash -is [System.IO.FileInfo]) { $Bash.FullName } elseif (-not [string]::IsNullOrWhiteSpace($Bash.Source)) { $Bash.Source } else { $Bash.Path }
if ([string]::IsNullOrWhiteSpace($BashPath)) { Fail 'Unable to resolve Bash executable path.' }
& $BashPath tools/security-audit.sh
if ($LASTEXITCODE -ne 0) { Fail 'Security source audit failed.' }
python tools/i18n-audit.py
if ($LASTEXITCODE -ne 0) { Fail 'i18n parity audit failed.' }

Write-Host '[2/5] Build and verify GaiaNet V2 helper transport'
& (Join-Path $PSScriptRoot 'build-go-netstack.ps1')
if ($LASTEXITCODE -ne 0) { Fail 'GaiaNet V2 helper build failed.' }

Write-Host '[3/5] Clean + core verification + debug APK'
& $Gradle.Source --no-daemon clean :core:coreCheck :app:assembleDebug
if ($LASTEXITCODE -ne 0) { Fail 'Gradle build/core verification failed.' }

Write-Host '[4/5] Android lint + packaged native-library audit'
& $Gradle.Source --no-daemon :app:lintDebug
if ($LASTEXITCODE -ne 0) { Fail 'Android lint failed.' }
$Apk = Join-Path $Root 'app\build\outputs\apk\debug\app-debug.apk'
if (-not (Test-Path -LiteralPath $Apk -PathType Leaf)) { Fail "Expected APK was not produced: $Apk" }
$Jar = Get-Command jar.exe -ErrorAction SilentlyContinue
if ($null -eq $Jar) { $Jar = Get-Command jar -ErrorAction SilentlyContinue }
if ($null -eq $Jar) { Fail 'JDK jar tool unavailable for APK native-library audit.' }
$Entries = (& $Jar.Source tf $Apk | Out-String)
foreach ($Required in @('lib/arm64-v8a/libgedefense_gaianet_v2.so','lib/x86_64/libgedefense_gaianet_v2.so')) {
    if ($Entries -notmatch [regex]::Escape($Required)) { Fail "APK is missing required GaiaNet V2 helper: $Required" }
}

Write-Host '[5/5] APK SHA-256'
$Hash = Get-FileHash -LiteralPath $Apk -Algorithm SHA256
Write-Host "APK: $Apk"
Write-Host "SHA-256: $($Hash.Hash.ToLowerInvariant())"
Write-Host 'BETA_BUILD_GATES_PASS. Real-device Full Flow tests remain mandatory before stable release.'
