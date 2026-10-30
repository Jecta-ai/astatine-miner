param(
    [Parameter(Mandatory = $true)][int]$ParentPid,
    [Parameter(Mandatory = $true)][string]$PlanPath
)

$ErrorActionPreference = 'Stop'
$Plan = Get-Content -LiteralPath $PlanPath -Raw | ConvertFrom-Json
$Applied = New-Object System.Collections.ArrayList
$LockStream = $null
$LockAcquired = $false
$Committed = $false

function ConvertTo-AstatineVersion([string]$Text) {
    $Match = [regex]::Match(
        $Text.Trim(),
        '^(?:astatine\s+)?(?<Major>0|[1-9][0-9]*)\.(?<Minor>0|[1-9][0-9]*)\.(?<Patch>0|[1-9][0-9]*)(?:-testnet\.(?<Sequence>0|[1-9][0-9]*))?$'
    )
    if (-not $Match.Success) { throw "Unsupported Astatine version format: $Text" }
    $Values = @(
        [System.UInt64]::Parse($Match.Groups['Major'].Value, [System.Globalization.CultureInfo]::InvariantCulture),
        [System.UInt64]::Parse($Match.Groups['Minor'].Value, [System.Globalization.CultureInfo]::InvariantCulture),
        [System.UInt64]::Parse($Match.Groups['Patch'].Value, [System.Globalization.CultureInfo]::InvariantCulture)
    )
    if ($Values | Where-Object { $_ -gt 2147483647 }) { throw "Astatine version component exceeds the supported SemVer range: $Text" }
    $IsPrerelease = $Match.Groups['Sequence'].Success
    $Sequence = [UInt64]0
    if ($IsPrerelease) {
        $Sequence = [System.UInt64]::Parse($Match.Groups['Sequence'].Value, [System.Globalization.CultureInfo]::InvariantCulture)
        if ($Sequence -gt 2147483647) { throw "Astatine prerelease identifier exceeds the supported SemVer range: $Text" }
    }
    return [pscustomobject]@{
        Major = $Values[0]
        Minor = $Values[1]
        Patch = $Values[2]
        IsPrerelease = $IsPrerelease
        Sequence = $Sequence
    }
}

function Compare-AstatineVersions([string]$Current, [string]$Candidate) {
    $CurrentParsed = ConvertTo-AstatineVersion $Current
    $CandidateParsed = ConvertTo-AstatineVersion $Candidate
    foreach ($Field in @('Major', 'Minor', 'Patch')) {
        if ($CurrentParsed.$Field -lt $CandidateParsed.$Field) { return -1 }
        if ($CurrentParsed.$Field -gt $CandidateParsed.$Field) { return 1 }
    }
    if ($CurrentParsed.IsPrerelease -ne $CandidateParsed.IsPrerelease) {
        if ($CurrentParsed.IsPrerelease) { return -1 }
        return 1
    }
    if ($CurrentParsed.IsPrerelease) {
        if ($CurrentParsed.Sequence -lt $CandidateParsed.Sequence) { return -1 }
        if ($CurrentParsed.Sequence -gt $CandidateParsed.Sequence) { return 1 }
    }
    return 0
}

try {
    while (Get-Process -Id $ParentPid -ErrorAction SilentlyContinue) {
        Start-Sleep -Milliseconds 200
    }
    $LockStream = [System.IO.File]::Open($Plan.lock, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite)
    $LockStream.Lock(0, 1)
    $LockAcquired = $true

    $CurrentOutput = & $Plan.executable --version 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'Refusing to update an executable whose installed version could not be read.' }
    $VersionOrder = Compare-AstatineVersions ($CurrentOutput -join "`n") $Plan.expected_version
    if ($VersionOrder -gt 0) {
        "Skipped stale Astatine update $($Plan.expected_version); $($CurrentOutput -join "`n") is newer." | Set-Content -LiteralPath $Plan.log -Encoding UTF8
        $Committed = $true
        return
    }

    foreach ($File in $Plan.files) {
        [void]$Applied.Add($File)
        if (Test-Path -LiteralPath $File.destination) {
            Move-Item -LiteralPath $File.destination -Destination $File.backup -Force
        }
        Move-Item -LiteralPath $File.staged -Destination $File.destination -Force
    }

    $VersionOutput = & $Plan.executable --version 2>&1
    if ($LASTEXITCODE -ne 0 -or (($VersionOutput -join "`n") -notmatch [regex]::Escape($Plan.expected_version))) {
        throw 'The installed executable failed its version smoke test.'
    }

    $Committed = $true
    foreach ($File in $Plan.files) {
        if (Test-Path -LiteralPath $File.backup) {
            Remove-Item -LiteralPath $File.backup -Force -ErrorAction SilentlyContinue
        }
    }
    try {
        "Installed Astatine $($Plan.expected_version)." | Set-Content -LiteralPath $Plan.log -Encoding UTF8
    } catch {
        # Installation is committed; diagnostic-log failures must not roll it back.
    }
} catch {
    if (-not $Committed) {
        for ($Index = $Applied.Count - 1; $Index -ge 0; $Index--) {
            $File = $Applied[$Index]
            try {
                if (Test-Path -LiteralPath $File.backup) {
                    if (Test-Path -LiteralPath $File.destination) {
                        Remove-Item -LiteralPath $File.destination -Force
                    }
                    Move-Item -LiteralPath $File.backup -Destination $File.destination -Force
                } elseif (-not (Test-Path -LiteralPath $File.staged) -and (Test-Path -LiteralPath $File.destination)) {
                    Remove-Item -LiteralPath $File.destination -Force
                }
            } catch {
                # Keep the backup in place if rollback itself is blocked by the OS.
            }
        }
    }
    ($_ | Out-String) | Set-Content -LiteralPath $Plan.log -Encoding UTF8
    exit 1
} finally {
    if ($LockAcquired) {
        $LockStream.Unlock(0, 1)
    }
    if ($null -ne $LockStream) {
        $LockStream.Dispose()
    }
    foreach ($File in $Plan.files) {
        if (Test-Path -LiteralPath $File.staged) {
            Remove-Item -LiteralPath $File.staged -Force -ErrorAction SilentlyContinue
        }
    }
}
