#requires -Version 7.0
param(
    [ValidateSet('win-x86', 'win-x64', 'win-arm64')]
    [string[]] $RuntimeIdentifier = @('win-x86', 'win-x64', 'win-arm64')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$build = Join-Path $PSScriptRoot '..\Build\Build.ps1'
[xml] $project = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\Code\Crypture.csproj') -Raw
$version = [string] $project.Project.PropertyGroup[0].Version
$testParent = [IO.DirectoryInfo]::new([IO.Path]::GetTempPath()).FullName.TrimEnd('\')
$testName = 'Crypture.Packaging-' + [Guid]::NewGuid().ToString('N')
$testDirectory = Join-Path $testParent $testName
$stage = Join-Path $testDirectory 'Stage'
$output = Join-Path $testDirectory 'Output'
$binaries = Join-Path $testDirectory 'Bin'
$arguments = @{ StageDirectory = $stage; OutputDirectory = $output; BinaryDirectory = $binaries; SkipSigning = $true }
$protectedStage = Join-Path $stage 'OtherBuild'
$firstRuntime = $RuntimeIdentifier[0]
$firstArch = $firstRuntime.Substring(4)
$installerName = "Crypture-$firstArch-$version-installer.msi"
$archives = @("Crypture-$version-portable.zip", "Crypture-$version-unpacked.zip")
$previous = 'Previous verified release'

function Assert-CleanStage
{
    $remaining = @(Get-ChildItem -LiteralPath $stage -Force)
    if ($remaining.Count -ne 1 -or $remaining[0].FullName -ne $protectedStage)
    {
        throw 'Packaging left its staging directory or removed another build.'
    }
}

try
{
    New-Item -ItemType Directory -Path $protectedStage, $output, $binaries | Out-Null
    foreach ($name in @($installerName) + $archives) { [IO.File]::WriteAllText((Join-Path $output $name), $previous) }

    # A late publication error must restore every previous artifact and leave other runs alone.
    $blocked = Join-Path $binaries $firstRuntime
    [IO.File]::WriteAllText($blocked, 'This path is occupied.')
    & $build @arguments -RuntimeIdentifier $firstRuntime
    if ($LASTEXITCODE -ne 1) { throw 'Packaging must fail when the binary output is blocked.' }
    foreach ($name in @($installerName) + $archives)
    {
        if ([IO.File]::ReadAllText((Join-Path $output $name)) -cne $previous)
        {
            throw "A failed build replaced $name."
        }
    }
    $files = @(Get-ChildItem -LiteralPath $output -Force)
    if ($files.Count -ne 3) { throw "Unexpected files after failed publication: $($files.Name -join ', ')" }
    Assert-CleanStage
    [IO.File]::Delete($blocked)

    # Verify a complete release through its normal entry point, including installer validation.
    & $build @arguments -RuntimeIdentifier $RuntimeIdentifier
    if ($LASTEXITCODE) { throw 'Packaging failed on its successful path.' }
    Assert-CleanStage
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    foreach ($name in $archives)
    {
        $archive = [IO.Compression.ZipFile]::OpenRead((Join-Path $output $name))
        try
        {
            foreach ($runtime in $RuntimeIdentifier)
            {
                $arch = $runtime.Substring(4)
                if (!$archive.GetEntry("$arch/Crypture.exe")) { throw "$name lacks the $arch executable." }
            }
        }
        finally { $archive.Dispose() }
    }
    foreach ($runtime in $RuntimeIdentifier)
    {
        $arch = $runtime.Substring(4)
        $installer = Get-Item -LiteralPath (Join-Path $output "Crypture-$arch-$version-installer.msi")
        if ($installer.Length -le $previous.Length) { throw "Missing $arch installer." }
        $reader = [IO.BinaryReader]::new([IO.File]::OpenRead((Join-Path $binaries "$runtime\Crypture.exe")))
        try
        {
            $reader.BaseStream.Position = 0x3C
            $reader.BaseStream.Position = $reader.ReadInt32() + 4
            if ($reader.ReadUInt16() -ne @{ x86 = 0x14C; x64 = 0x8664; arm64 = 0xAA64 }[$arch])
            {
                throw "The $arch executable has the wrong PE machine type."
            }
        }
        finally { $reader.Dispose() }
    }
    Write-Output "Passed release publication, rollback, stage cleanup, and package checks for $RuntimeIdentifier."
}
finally
{
    $run = Get-Item -LiteralPath $testDirectory -ErrorAction SilentlyContinue
    if ($run -and $run.Parent.FullName -eq $testParent -and $run.Name -eq $testName -and
        !($run.Attributes -band [IO.FileAttributes]::ReparsePoint))
    {
        Remove-Item -LiteralPath $run.FullName -Recurse -Force
    }
}
