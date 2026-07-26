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

function New-StreamCapture {
    param([System.IO.Stream]$Stream)

    $buffer = [byte[]]::new(8192)
    return [pscustomobject]@{
        Buffer = $buffer
        Complete = $false
        Output = [System.IO.MemoryStream]::new()
        Stream = $Stream
        Task = $Stream.ReadAsync($buffer, 0, $buffer.Length)
    }
}

function Read-StreamCapture {
    param(
        [pscustomobject]$Run,
        [pscustomobject]$Capture
    )

    while (-not $Capture.Complete -and $Capture.Task.IsCompleted) {
        $Capture.Complete = $true
        $count = $Capture.Task.GetAwaiter().GetResult()
        if ($count -eq 0) {
            return $false
        }
        if ($Run.OutputBytes + $count -gt $maximumOutputBytes) {
            return $true
        }
        $Capture.Output.Write($Capture.Buffer, 0, $count)
        $Run.OutputBytes += $count
        $Capture.Task = $Capture.Stream.ReadAsync(
            $Capture.Buffer,
            0,
            $Capture.Buffer.Length
        )
        $Capture.Complete = $false
    }
    return $false
}

function Join-Failure {
    param(
        [string]$Current,
        [string]$Next
    )

    if ($Current) {
        return "$Current; $Next"
    }
    return $Next
}

function Remove-Directory {
    param([string]$Path)

    for ($attempt = 1; $attempt -le 20; $attempt++) {
        try {
            [System.IO.Directory]::Delete($Path, $true)
            return $null
        } catch {
            if ($attempt -eq 20) {
                return $_.Exception.Message
            }
            Start-Sleep -Milliseconds 250
        }
    }
}

$checks = @(
    @{
        Name = 'Git Bash'
        File = 'C:\Program Files\Git\bin\bash.exe'
        Arguments = @(
            '--noprofile',
            '--norc',
            '-c',
            'export CELESTIA_CACHE_DIR="$("/usr/bin/cygpath" "$CELESTIA_SHELL_CACHE")" CARGO_TARGET_DIR="$("/usr/bin/cygpath" "$CELESTIA_SHELL_TARGET")" TMPDIR="$("/usr/bin/cygpath" "$CELESTIA_SHELL_TMP")"; exec /usr/bin/bash ./.github/scripts/devcheck.sh'
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
            'export CELESTIA_CACHE_DIR="$("/usr/bin/cygpath" "$CELESTIA_SHELL_CACHE")" CARGO_TARGET_DIR="$("/usr/bin/cygpath" "$CELESTIA_SHELL_TARGET")" TMPDIR="$("/usr/bin/cygpath" "$CELESTIA_SHELL_TMP")"; exec /usr/bin/bash ./.github/scripts/devcheck.sh'
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
            'cd "$(/usr/bin/cygpath "$GITHUB_WORKSPACE")" || exit; export CELESTIA_CACHE_DIR="$("/usr/bin/cygpath" "$CELESTIA_SHELL_CACHE")" CARGO_TARGET_DIR="$("/usr/bin/cygpath" "$CELESTIA_SHELL_TARGET")" TMPDIR="$("/usr/bin/cygpath" "$CELESTIA_SHELL_TMP")"; exec /usr/bin/bash ./.github/scripts/devcheck.sh'
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
$mutableRoot = Join-Path $root ".cache\windows-shell\$runID"
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
        $start = [System.Diagnostics.ProcessStartInfo]::new()
        $start.FileName = $check.File
        $start.WorkingDirectory = $root
        $start.UseShellExecute = $false
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $start.Environment['DEVCHECK_CURRENCY'] = 'false'
        $start.Environment['DEVCHECK_PROFILE'] = 'shell'
        $start.Environment['GITHUB_WORKSPACE'] = $root
        $start.Environment['CELESTIA_SHELL_CACHE'] = (
            Join-Path $shellRoot 'cache'
        )
        $start.Environment['CELESTIA_SHELL_TARGET'] = (
            Join-Path $shellRoot 'target'
        )
        $start.Environment['CELESTIA_SHELL_TMP'] = (
            Join-Path $shellRoot 'tmp'
        )
        $start.Environment['TEMP'] = (Join-Path $shellRoot 'tmp')
        $start.Environment['TMP'] = (Join-Path $shellRoot 'tmp')
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
            OutputBytes = 0
            Process = $process
            StandardError = New-StreamCapture -Stream (
                $process.StandardError.BaseStream
            )
            StandardOutput = New-StreamCapture -Stream (
                $process.StandardOutput.BaseStream
            )
        }
    }

    while (-not $failure) {
        $allExited = $true
        foreach ($run in $running) {
            $overflow = (
                (Read-StreamCapture -Run $run -Capture $run.StandardOutput) -or
                (Read-StreamCapture -Run $run -Capture $run.StandardError)
            )
            if ($overflow) {
                $failure = "$($run.Name) exceeded the output limit"
                break
            }
            if (
                -not $run.Process.HasExited -or
                -not $run.StandardOutput.Complete -or
                -not $run.StandardError.Complete
            ) {
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
                $failure = Join-Failure -Current $failure -Next (
                    "$($run.Name) could not be terminated: $($_.Exception.Message)"
                )
            }
        }
    }
    foreach ($run in $running) {
        $terminated = $false
        try {
            $terminated = $run.Process.WaitForExit(5000)
            if (-not $terminated) {
                $failure = Join-Failure -Current $failure -Next (
                    "$($run.Name) did not terminate"
                )
            }
        } catch {
            $failure = Join-Failure -Current $failure -Next (
                "$($run.Name) could not be reaped: $($_.Exception.Message)"
            )
        }
        $drainDeadline = [DateTime]::UtcNow.AddSeconds(5)
        while (
            $terminated -and
            (
                -not $run.StandardOutput.Complete -or
                -not $run.StandardError.Complete
            )
        ) {
            $overflow = (
                (Read-StreamCapture -Run $run -Capture $run.StandardOutput) -or
                (Read-StreamCapture -Run $run -Capture $run.StandardError)
            )
            if ($overflow) {
                $failure = Join-Failure -Current $failure -Next (
                    "$($run.Name) exceeded the output limit"
                )
            }
            if ([DateTime]::UtcNow -ge $drainDeadline) {
                $failure = Join-Failure -Current $failure -Next (
                    "$($run.Name) output did not close"
                )
                break
            }
            Start-Sleep -Milliseconds 10
        }
        if (
            -not $run.StandardOutput.Complete -or
            -not $run.StandardError.Complete
        ) {
            $run.StandardOutput.Stream.Dispose()
            $run.StandardError.Stream.Dispose()
            $run.StandardOutput.Complete = $true
            $run.StandardError.Complete = $true
        }
    }
}

foreach ($run in $running) {
    Write-Output "`n==> $($run.Name)"
    $stdout = [System.Text.Encoding]::UTF8.GetString(
        $run.StandardOutput.Output.ToArray()
    )
    $stderr = [System.Text.Encoding]::UTF8.GetString(
        $run.StandardError.Output.ToArray()
    )
    if ($stdout) {
        Write-Output $stdout.TrimEnd()
    }
    if ($stderr) {
        [Console]::Error.WriteLine($stderr.TrimEnd())
    }
    $run.StandardOutput.Output.Dispose()
    $run.StandardError.Output.Dispose()
    $run.Process.Dispose()
}

$cleanupFailures = @(
    @(
        Remove-Directory -Path $mutableRoot
    ) | Where-Object { $_ }
)
if ($cleanupFailures.Count -gt 0) {
    $cleanupFailure = 'Windows shell cleanup failed: ' + (
        $cleanupFailures -join '; '
    )
    if ($failure) {
        $failure += "; $cleanupFailure"
    } else {
        $failure = $cleanupFailure
    }
}
if ($failure) {
    [Console]::Error.WriteLine($failure)
    exit 1
}
