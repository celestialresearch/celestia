# Copyright © 2026 @sudocelestia. All rights reserved.
#
# PROPRIETARY AND CONFIDENTIAL SOURCE CODE.
#
# No licence, permission or authorisation is granted to use, copy, modify,
# compile, execute, distribute, publish, sublicense or otherwise exploit this
# file, except to the limited extent unavoidably permitted by applicable law
# or GitHub's Terms of Service.
#
# See the LICENSE file at the repository root for the complete terms.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = (Resolve-Path -LiteralPath "$PSScriptRoot\..\..").Path
$maximumOutputBytes = 1MB
$shellDeadline = [TimeSpan]::FromMinutes(10)
$outputLimit = $maximumOutputBytes + 1
$checks = @(
    @{
        Name = 'Git Bash'
        File = 'C:\Program Files\Git\bin\bash.exe'
        Arguments = @(
            '--noprofile',
            '--norc',
            '-c',
            'set -o pipefail; /usr/bin/bash ./.github/scripts/devcheck.sh 2>&1 | head -c "$CELESTIA_SHELL_OUTPUT_LIMIT" > "$(/usr/bin/cygpath "$CELESTIA_SHELL_LOG")"'
        )
        Environment = @{}
    },
    @{
        Name = 'MSYS2'
        File = 'C:\msys64\usr\bin\bash.exe'
        Arguments = @(
            '--noprofile',
            '--norc',
            '-c',
            'set -o pipefail; /usr/bin/bash ./.github/scripts/devcheck.sh 2>&1 | head -c "$CELESTIA_SHELL_OUTPUT_LIMIT" > "$(/usr/bin/cygpath "$CELESTIA_SHELL_LOG")"'
        )
        Environment = @{
            CHERE_INVOKING = '1'
            MSYSTEM = 'UCRT64'
        }
    },
    @{
        Name = 'Cygwin'
        File = 'C:\cygwin\bin\bash.exe'
        Arguments = @(
            '--login',
            '-o',
            'igncr',
            '-c',
            'cd "$(/usr/bin/cygpath "$GITHUB_WORKSPACE")" || exit; set -o pipefail; /usr/bin/bash ./.github/scripts/devcheck.sh 2>&1 | head -c "$CELESTIA_SHELL_OUTPUT_LIMIT" > "$(/usr/bin/cygpath "$CELESTIA_SHELL_LOG")"'
        )
        Environment = @{}
    }
)

foreach ($check in $checks) {
    if (-not (Test-Path -LiteralPath $check.File -PathType Leaf)) {
        throw "$($check.Name) executable does not exist: $($check.File)"
    }
}

$runID = [guid]::NewGuid().ToString('N')
$logRoot = Join-Path ([System.IO.Path]::GetTempPath()) "celestia-shellcheck-$runID"
$mutableRoot = Join-Path $root ".cache\windows-shell\$runID"
[System.IO.Directory]::CreateDirectory($logRoot) | Out-Null
[System.IO.Directory]::CreateDirectory($mutableRoot) | Out-Null
$running = @()
$failure = $null
$deadline = [DateTime]::UtcNow + $shellDeadline

try {
    foreach ($check in $checks) {
        $shellName = $check.Name.Replace(' ', '-').ToLowerInvariant()
        $shellRoot = Join-Path $mutableRoot $shellName
        [System.IO.Directory]::CreateDirectory(
            (Join-Path $shellRoot 'cache')
        ) | Out-Null
        [System.IO.Directory]::CreateDirectory(
            (Join-Path $shellRoot 'target')
        ) | Out-Null
        [System.IO.Directory]::CreateDirectory(
            (Join-Path $shellRoot 'tmp')
        ) | Out-Null
        $relativeRoot = ".cache/windows-shell/$runID/$shellName"
        $log = Join-Path $logRoot "$shellName.log"
        $start = [System.Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $check.File
        $start.WorkingDirectory = $root
        $start.UseShellExecute = $false
        $start.Environment['CELESTIA_SHELL_LOG'] = $log
        $start.Environment['CELESTIA_SHELL_OUTPUT_LIMIT'] = [string]$outputLimit
        $start.Environment['DEVCHECK_CURRENCY'] = 'false'
        $start.Environment['DEVCHECK_PROFILE'] = 'shell'
        $start.Environment['GITHUB_WORKSPACE'] = $root
        $start.Environment['CELESTIA_CACHE_DIR'] = "$relativeRoot/cache"
        $start.Environment['CARGO_TARGET_DIR'] = "$relativeRoot/target"
        $start.Environment['TMPDIR'] = "$relativeRoot/tmp"
        foreach ($entry in $check.Environment.GetEnumerator()) {
            $start.Environment[$entry.Key] = $entry.Value
        }
        foreach ($argument in $check.Arguments) {
            $start.ArgumentList.Add($argument)
        }

        $process = [System.Diagnostics.Process]::new()
        $process.StartInfo = $start
        if (-not $process.Start()) {
            throw "Failed to start $($check.Name)"
        }
        $running += [pscustomobject]@{
            Name = $check.Name
            Log = $log
            Process = $process
        }
    }

    while (-not $failure) {
        $allExited = $true
        foreach ($run in $running) {
            if (Test-Path -LiteralPath $run.Log -PathType Leaf) {
                $length = (Get-Item -LiteralPath $run.Log).Length
                if ($length -gt $maximumOutputBytes) {
                    $failure = "$($run.Name) exceeded the output limit"
                    break
                }
            }
            if (-not $run.Process.HasExited) {
                $allExited = $false
            } elseif ($run.Process.ExitCode -ne 0) {
                $failure = "$($run.Name) failed with exit code $($run.Process.ExitCode)"
                break
            }
        }
        if ($allExited -or $failure) {
            break
        }
        if ([DateTime]::UtcNow -ge $deadline) {
            $failure = 'Windows shell verification exceeded its deadline'
            break
        }
        Start-Sleep -Milliseconds 100
    }
} catch {
    $failure = $_.Exception.Message
} finally {
    foreach ($run in $running) {
        if (-not $run.Process.HasExited) {
            try {
                $run.Process.Kill($true)
            } catch {
                $failure = "$($run.Name) could not be terminated: $($_.Exception.Message)"
            }
        }
    }
    foreach ($run in $running) {
        try {
            if (-not $run.Process.WaitForExit(5000)) {
                $failure = "$($run.Name) did not terminate"
            }
        } catch {
            $failure = "$($run.Name) could not be reaped: $($_.Exception.Message)"
        }
    }
}

foreach ($run in $running) {
    Write-Output "`n==> $($run.Name)"
    if (Test-Path -LiteralPath $run.Log -PathType Leaf) {
        $output = Get-Content -LiteralPath $run.Log -Raw
        if ($output) {
            Write-Output $output.TrimEnd()
        }
    }
    $run.Process.Dispose()
}

[System.IO.Directory]::Delete($logRoot, $true)
[System.IO.Directory]::Delete($mutableRoot, $true)
if ($failure) {
    [Console]::Error.WriteLine($failure)
    exit 1
}
