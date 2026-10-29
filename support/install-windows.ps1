$ErrorActionPreference = 'Stop'
$Version = '0.1.0-testnet.12'
$Asset = 'astatine-windows-x86_64.zip'
$Base = "https://github.com/emyrinj/astatine-miner/releases/download/v$Version"
$Temp = Join-Path $env:TEMP ("astatine-install-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Temp | Out-Null
try {
    $Manifest = Join-Path $Temp 'update-manifest.txt'
    $Signature = Join-Path $Temp 'update-manifest.sig'
    Invoke-WebRequest -Uri "$Base/update-manifest.txt" -OutFile $Manifest -TimeoutSec 60
    Invoke-WebRequest -Uri "$Base/update-manifest.sig" -OutFile $Signature -TimeoutSec 60
    if ((Get-Item -LiteralPath $Manifest).Length -gt 2097152) { throw 'Release manifest exceeds its size limit' }
    if ((Get-Item -LiteralPath $Signature).Length -ne 384) { throw 'Release signature has an invalid length' }

    $KeyXml = '<RSAKeyValue><Modulus>vFRqlV94vTfLogc01RAkRPzmEYGO62akKkOLpBtaBqemy4gjOpDZAjSWn2wsPilPAvGQT2UWvck56GlUbv7vRzz17AvPf7cwKv+hYGCQA/5WEmhxhgLUSei44ihW5AAFC068U8iD37CwMEPDy23u4jl35HKwvEd5xasdaz8db8cX/9pquUdOL3mGnPpTXkzZqQHnkEEA42jKo8jKpl0IDTlVoKZ8Kdw6BBnzGLhizJtZGiDj5J3hH5YHrT5weh8RBDnqKSj8xNiGhgsDh5xVTUsttFfjlOFHrCHrkED3+UG01xJ5PYFyos4QSO7feLkbjlpOfh1x8pMlQ96YXIZ3mxNDltLgXqJ98/IzVvp/ewLmIkGY6pW5Exlvdbz6nfgtcbaiXCi9MwbevAojzLJ1V/wps7F/hyuv9dKSRIoaRIHkgSnA6YP8epTnJn+swL9LHdZjayS1vkXf8s46IAaLyh8ts3pJY8Tb5gAIzJ6OvDxijD1AnnhrMEew9lcVVW6H</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>'
    $Rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider
    $Rsa.FromXmlString($KeyXml)
    $ManifestBytes = [System.IO.File]::ReadAllBytes($Manifest)
    $SignatureBytes = [System.IO.File]::ReadAllBytes($Signature)
    if ($SignatureBytes.Length -ne 384) { throw 'Release signature has an invalid length' }
    $Sha256Oid = [System.Security.Cryptography.CryptoConfig]::MapNameToOID('SHA256')
    if (-not $Rsa.VerifyData($ManifestBytes, $Sha256Oid, $SignatureBytes)) {
        throw 'Release manifest signature verification failed'
    }
    $ManifestLines = Get-Content -LiteralPath $Manifest
    if ($ManifestLines[0] -ne 'astatine-update-manifest-v1') { throw 'Unsupported release manifest format' }
    if ($ManifestLines -notcontains 'repository=emyrinj/astatine-miner') { throw 'Manifest repository identity is invalid' }
    if ($ManifestLines -notcontains 'channel=testnet') { throw 'Manifest channel is not Testnet' }
    $VersionLine = $ManifestLines | Where-Object { $_.StartsWith('version=') }
    if ($VersionLine -ne "version=$Version") { throw 'Signed manifest version does not match this installer' }
    $AssetLine = $ManifestLines | Where-Object { $_.StartsWith('asset.package.windows-x86_64=') }
    if (-not $AssetLine) { throw 'Signed manifest has no Windows package' }
    $Record = $AssetLine.Substring($AssetLine.IndexOf('=') + 1).Split('|')
    if ($Record.Count -ne 3 -or $Record[0] -ne $Asset) { throw 'Signed Windows package record is malformed' }

    $Archive = Join-Path $Temp $Asset
    Invoke-WebRequest -Uri "$Base/$Asset" -OutFile $Archive -TimeoutSec 180
    if ((Get-FileHash -Path $Archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Record[1]) {
        throw 'Windows package SHA-256 does not match the signed manifest'
    }
    if ((Get-Item -LiteralPath $Archive).Length -ne [Int64]$Record[2]) {
        throw 'Windows package length does not match the signed manifest'
    }

    $Extract = Join-Path $Temp 'extracted'
    Expand-Archive -LiteralPath $Archive -DestinationPath $Extract
    $Entries = @(Get-ChildItem -LiteralPath $Extract -File | ForEach-Object { $_.Name } | Sort-Object)
    $Expected = @('LICENSE-MIT', 'THIRD_PARTY_LICENSES.md', 'astatine.exe') | Sort-Object
    if (($Entries -join '|') -ne ($Expected -join '|')) { throw 'Windows archive contains unexpected files' }
    $StagedExe = Join-Path $Extract 'astatine.exe'
    $VersionOutput = & $StagedExe --version
    if ($LASTEXITCODE -ne 0 -or ($VersionOutput -notmatch [regex]::Escape($Version))) {
        throw 'Downloaded executable failed its version smoke test'
    }

    $InstallDir = Join-Path $HOME 'bin'
    $ExistingExe = Join-Path $InstallDir 'astatine.exe'
    if (Test-Path -LiteralPath $ExistingExe) {
        $ExistingVersionOutput = & $ExistingExe --version 2>$null
        if ($LASTEXITCODE -eq 0 -and $ExistingVersionOutput -match 'astatine\s+0\.1\.0-testnet\.(\d+)') {
            $InstalledSequence = [Int64]::Parse($Matches[1])
            $CandidateSequence = [Int64]::Parse($Version.Split('.')[-1])
            if ($InstalledSequence -gt $CandidateSequence) {
                throw "Refusing to replace newer Astatine $($Matches[0]) with $Version"
            }
        }
    }
    $LicenseDir = Join-Path $InstallDir 'licenses'
    New-Item -ItemType Directory -Path $LicenseDir -Force | Out-Null
    $Files = @(
        @{ Source = $StagedExe; Destination = (Join-Path $InstallDir 'astatine.exe') },
        @{ Source = (Join-Path $Extract 'LICENSE-MIT'); Destination = (Join-Path $LicenseDir 'LICENSE-MIT') },
        @{ Source = (Join-Path $Extract 'THIRD_PARTY_LICENSES.md'); Destination = (Join-Path $LicenseDir 'THIRD_PARTY_LICENSES.md') }
    )
    $Backups = @()
    try {
        foreach ($File in $Files) {
            $Stage = "$($File.Destination).update"
            $Backup = "$($File.Destination).backup"
            Copy-Item -LiteralPath $File.Source -Destination $Stage -Force
            $HadOriginal = Test-Path -LiteralPath $File.Destination
            if ($HadOriginal) { Move-Item -LiteralPath $File.Destination -Destination $Backup -Force }
            $Backups += @{ Destination = $File.Destination; Backup = $Backup; HadOriginal = $HadOriginal }
            Move-Item -LiteralPath $Stage -Destination $File.Destination -Force
        }
        $InstalledVersion = & (Join-Path $InstallDir 'astatine.exe') --version
        if ($LASTEXITCODE -ne 0 -or ($InstalledVersion -notmatch [regex]::Escape($Version))) {
            throw 'Installed executable failed its version smoke test'
        }
        foreach ($Backup in $Backups) {
            if ($Backup.HadOriginal) { Remove-Item -LiteralPath $Backup.Backup -Force }
        }
    } catch {
        for ($Index = $Backups.Count - 1; $Index -ge 0; $Index--) {
            $Backup = $Backups[$Index]
            if (Test-Path -LiteralPath $Backup.Destination) { Remove-Item -LiteralPath $Backup.Destination -Force }
            if ($Backup.HadOriginal -and (Test-Path -LiteralPath $Backup.Backup)) {
                Move-Item -LiteralPath $Backup.Backup -Destination $Backup.Destination -Force
            }
        }
        throw
    }
    & (Join-Path $InstallDir 'astatine.exe') --version
    Write-Host "Installed authenticated Astatine $Version in $InstallDir"
} finally {
    Remove-Item -LiteralPath $Temp -Recurse -Force -ErrorAction SilentlyContinue
}
