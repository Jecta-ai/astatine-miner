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

function Get-TestnetVersion([string]$Text) {
    $Match = [regex]::Match($Text, 'astatine\s+(\d+)\.(\d+)\.(\d+)-testnet\.(\d+)')
    if (-not $Match.Success) { return $null }
    return [pscustomobject]@{
        Core = [Version]::Parse("$($Match.Groups[1].Value).$($Match.Groups[2].Value).$($Match.Groups[3].Value)")
        Sequence = [UInt64]::Parse($Match.Groups[4].Value)
    }
}

try {
    while (Get-Process -Id $ParentPid -ErrorAction SilentlyContinue) {
        Start-Sleep -Milliseconds 200
    }
    $LockStream = [System.IO.File]::Open($Plan.lock, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite)
    $LockStream.Lock(0, 1)
    $LockAcquired = $true

    $CurrentOutput = & $Plan.executable --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        $Current = Get-TestnetVersion ($CurrentOutput -join "`n")
        $Candidate = Get-TestnetVersion $Plan.expected_version
        if ($null -ne $Current -and $null -ne $Candidate -and $Current.Core -eq $Candidate.Core -and $Current.Sequence -gt $Candidate.Sequence) {
            "Skipped stale Astatine update $($Plan.expected_version); $($CurrentOutput -join "`n") is newer." | Set-Content -LiteralPath $Plan.log -Encoding UTF8
            $Committed = $true
            return
        }
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
