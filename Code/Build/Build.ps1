#requires -Version 5.1
param(
    [string] $BinaryDirectory = "$PSScriptRoot\..\bin\Release\Portable\win-x64",
    [string] $OutputDirectory = "$PSScriptRoot\..\..\Binaries",
    [string] $StageDirectory = "$PSScriptRoot\PackageStage",
    [string] $TimestampUrl = 'http://timestamp.digicert.com',
    [string] $ProductName = 'Crypture',
    [string] $ProductUrl = 'https://github.com/NoMoreFood/Crypture',
    [ValidateSet('win-x64', 'win-x86', 'win-arm64')][string] $RuntimeIdentifier = 'win-x64',
    [switch] $SkipSigning
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Tool([string] $Path, [string[]] $Arguments)
{
    & $Path @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Path failed with exit code $LASTEXITCODE." }
}

try
{
    $project = [IO.Path]::GetFullPath("$PSScriptRoot\..\Crypture.csproj")
    $BinaryDirectory = [IO.Path]::GetFullPath($BinaryDirectory)
    $OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
    $StageDirectory = [IO.Path]::GetFullPath($StageDirectory)
    [xml] $projectSource = Get-Content -LiteralPath $project -Raw
    $version = [string] $projectSource.Project.PropertyGroup[0].Version
    $packageName = "Crypture-$version-$RuntimeIdentifier-portable.exe"
    $destination = Join-Path $OutputDirectory $packageName
    if (Test-Path -LiteralPath $destination) { throw "Package already exists: $destination" }

    # Use a fresh staging folder so existing artifacts and signed outputs remain intact.
    $stage = Join-Path $StageDirectory ([Guid]::NewGuid().ToString('N'))
    $publishDirectory = Join-Path $stage 'Publish'
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    $dotnet = (Get-Command dotnet.exe -CommandType Application -ErrorAction Stop).Source
    Invoke-Tool $dotnet @('restore', $project, '--runtime', $RuntimeIdentifier, '--verbosity', 'minimal',
        '-p:SelfContained=true')

    # Embed the runtime and every distributed dependency's license/notice text in About.
    $assetsPath = Join-Path (Split-Path -Parent $project) 'obj\project.assets.json'
    $assets = Get-Content -LiteralPath $assetsPath -Raw | ConvertFrom-Json
    $packageRoot = $assets.packageFolders.PSObject.Properties.Name | Select-Object -First 1
    $notices = Join-Path $stage 'RuntimeNotices.txt'
    $texts = [Collections.Generic.List[string]]::new()
    foreach ($library in $assets.libraries.PSObject.Properties)
    {
        if ($library.Value.type -ne 'package') { continue }
        $packageDirectory = Join-Path $packageRoot $library.Value.path
        [xml] $manifest = Get-Content -LiteralPath (Get-ChildItem -LiteralPath $packageDirectory `
            -Filter '*.nuspec' | Select-Object -First 1).FullName -Raw
        $metadata = $manifest.package.metadata
        if ($metadata.PSObject.Properties['license'])
        {
            $license = $metadata.license
            $texts.Add("$($library.Name)`r`n" + $(if ($license.type -eq 'expression') {
                [string] (Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/spdx/license-list-data/main/text/$($license.'#text').txt").Content
            } else { Get-Content -LiteralPath (Join-Path $packageDirectory $license.'#text') -Raw }))
        }
    }
    foreach ($runtime in @('microsoft.netcore.app.runtime', 'microsoft.windowsdesktop.app.runtime'))
    {
        $runtimeDirectory = Join-Path $packageRoot "$runtime.$RuntimeIdentifier"
        $runtimePackage = Get-ChildItem -LiteralPath $runtimeDirectory -Directory |
            Where-Object { $_.Name -match '^10\.0\.\d+$' } |
            Sort-Object { [version] $_.Name } -Descending | Select-Object -First 1
        if (!$runtimePackage) { throw "The .NET 10 runtime package was not restored: $runtimeDirectory" }
        foreach ($file in Get-ChildItem -LiteralPath $runtimePackage.FullName -File |
            Where-Object { $_.Name -match 'LICENSE|NOTICE' })
        {
            $texts.Add("$runtime $($runtimePackage.Name)`r`n" + (Get-Content -LiteralPath $file.FullName -Raw))
        }
    }
    [IO.File]::WriteAllText($notices, ($texts -join "`r`n`r`n"), [Text.UTF8Encoding]::new($false))

    Write-Host "Publishing Crypture $version as an English-only, self-contained $RuntimeIdentifier EXE."
    Invoke-Tool $dotnet @('publish', $project, '--configuration', 'Release', '--runtime', $RuntimeIdentifier,
        '--no-restore', '--verbosity', 'minimal', '-p:PublishProfile=Portable',
        "-p:PublishDir=$publishDirectory/", "-p:RuntimeNoticesFile=$notices")
    $payload = @(Get-ChildItem -LiteralPath $publishDirectory -Force)
    if ($payload.Count -ne 1 -or $payload[0].Name -ne 'Crypture.exe')
    {
        throw 'Publishing must produce exactly one file, Crypture.exe, with no external dependencies.'
    }
    $executable = $payload[0].FullName
    if ([version] (Get-Item -LiteralPath $executable).VersionInfo.FileVersion -ne [version] "$version.0")
    {
        throw 'The built executable does not match the release version.'
    }

    if (!$SkipSigning)
    {
        $sdkRoot = Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots' `
            -Name KitsRoot10 -ErrorAction SilentlyContinue
        if (!$sdkRoot) { $sdkRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10' }
        $hostArchitecture = $env:PROCESSOR_ARCHITECTURE
        if ($env:PROCESSOR_ARCHITEW6432) { $hostArchitecture = $env:PROCESSOR_ARCHITEW6432 }
        $toolArchitecture = switch ($hostArchitecture) { 'ARM64' { 'arm64' } 'AMD64' { 'x64' } default { 'x86' } }
        $signTool = Get-ChildItem -LiteralPath (Join-Path $sdkRoot 'bin') -Directory |
            Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } |
            Sort-Object { [version] $_.Name } -Descending |
            ForEach-Object { Join-Path $_.FullName "$toolArchitecture\signtool.exe" } |
            Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
        if (!$signTool) { throw 'Install the Windows SDK signing tools, or use -SkipSigning for an unsigned build.' }

        $signOptions = @('sign', '/a', '/fd', 'sha256',
            '/d', $ProductName, '/du', $ProductUrl)
        $signingStore = $null
        $now = Get-Date
        foreach ($location in @('CurrentUser', 'LocalMachine'))
        {
            $certificateStore = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', $location)
            try
            {
                $certificateStore.Open('ReadOnly, OpenExistingOnly')
                $certificates = @($certificateStore.Certificates.Find('FindByApplicationPolicy',
                    '1.3.6.1.5.5.7.3.3', $true) | Where-Object {
                    $_.HasPrivateKey -and $_.NotBefore -le $now -and $_.NotAfter -gt $now
                })
                if ($certificates.Count -eq 0) { continue }
                $signingStore = $location
                $signingThumbprint = ($certificates | Sort-Object NotAfter -Descending |
                    Select-Object -First 1).Thumbprint
                break
            }
            finally
            {
                $certificateStore.Dispose()
            }
        }
        if (!$signingStore) { throw 'No trusted, valid code-signing certificate was found. Use -SkipSigning if needed.' }
        if ($signingStore -eq 'LocalMachine') { $signOptions += '/sm' }
        $signOptions += @('/sha1', $signingThumbprint)
        Invoke-Tool $signTool ($signOptions + $executable)
        Invoke-Tool $signTool @('timestamp', '/tr', $TimestampUrl, '/td', 'sha256', $executable)
        Invoke-Tool $signTool @('verify', '/pa', '/tw', $executable)
    }

    New-Item -ItemType Directory -Path $BinaryDirectory, $OutputDirectory -Force | Out-Null
    Copy-Item -LiteralPath $executable -Destination (Join-Path $BinaryDirectory 'Crypture.exe') -Force
    [IO.File]::Copy($executable, $destination, $false)
    Write-Host "Portable EXE ready: $destination"
}
catch
{
    Write-Error "Packaging failed: $($_.Exception.Message)" -ErrorAction Continue
    exit 1
}
