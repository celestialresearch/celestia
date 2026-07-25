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
$checks = @(
    @{
        Name = 'Git Bash'
        File = 'C:\Program Files\Git\bin\bash.exe'
        Arguments = @('--noprofile', '--norc', '-c', 'bash ./.github/scripts/devcheck.sh')
        Environment = @{}
    },
    @{
        Name = 'MSYS2'
        File = 'C:\msys64\usr\bin\bash.exe'
        Arguments = @('--noprofile', '--norc', '-c', 'bash ./.github/scripts/devcheck.sh')
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
            'cd "$(cygpath "$GITHUB_WORKSPACE")" && bash ./.github/scripts/devcheck.sh'
        )
        Environment = @{}
    }
)

$running = foreach ($check in $checks) {
    if (-not (Test-Path -LiteralPath $check.File -PathType Leaf)) {
        throw "$($check.Name) executable does not exist: $($check.File)"
    }

    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $check.File
    $start.WorkingDirectory = $root
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.Environment['DEVCHECK_CURRENCY'] = 'false'
    $start.Environment['DEVCHECK_PROFILE'] = 'shell'
    $start.Environment['GITHUB_WORKSPACE'] = $root
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
    [pscustomobject]@{
        Name = $check.Name
        Process = $process
        StandardOutput = $process.StandardOutput.ReadToEndAsync()
        StandardError = $process.StandardError.ReadToEndAsync()
    }
}

$failed = $false
foreach ($run in $running) {
    $run.Process.WaitForExit()
    $output = $run.StandardOutput.GetAwaiter().GetResult()
    $errorOutput = $run.StandardError.GetAwaiter().GetResult()
    Write-Output "`n==> $($run.Name)"
    if ($output) {
        Write-Output $output.TrimEnd()
    }
    if ($errorOutput) {
        [Console]::Error.WriteLine($errorOutput.TrimEnd())
    }
    if ($run.Process.ExitCode -ne 0) {
        $failed = $true
        [Console]::Error.WriteLine(
            "$($run.Name) failed with exit code $($run.Process.ExitCode)"
        )
    }
    $run.Process.Dispose()
}

if ($failed) {
    exit 1
}
