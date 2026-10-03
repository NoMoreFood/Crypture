#requires -Version 5.1
param(
    [string] $BinaryDirectory = "$PSScriptRoot\..\Code\bin\Release\Portable",
    [string] $OutputDirectory = "$PSScriptRoot\..\Binaries",
    [string] $StageDirectory = "$PSScriptRoot\PackageStage",
    [string] $TimestampUrl = 'http://timestamp.digicert.com',
    [string] $ProductName = 'Crypture',
    [string] $ProductUrl = 'https://github.com/NoMoreFood/Crypture',
    [ValidateSet('win-x64', 'win-x86', 'win-arm64')][string[]] $RuntimeIdentifier = @('win-x64', 'win-arm64'),
    [switch] $SkipSigning
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Tool([string] $Path, [string[]] $Arguments)
{
    & $Path @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Path failed with exit code $LASTEXITCODE." }
}

function Sign-File([string] $Path)
{
    if ($SkipSigning) { return }
    Invoke-Tool $signTool ($signOptions + $Path)
    Invoke-Tool $signTool @('timestamp', '/tr', $TimestampUrl, '/td', 'sha256', $Path)
    Invoke-Tool $signTool @('verify', '/pa', '/tw', $Path)
}

try
{
    $project = [IO.Path]::GetFullPath("$PSScriptRoot\..\Code\Crypture.csproj")
    $BinaryDirectory = [IO.Path]::GetFullPath($BinaryDirectory)
    $OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
    $StageDirectory = [IO.Path]::GetFullPath($StageDirectory)
    [xml] $projectSource = Get-Content -LiteralPath $project -Raw
    $version = [string] $projectSource.Project.PropertyGroup[0].Version
    $packageName = "Crypture-$version-portable.zip"
    $destination = Join-Path $OutputDirectory $packageName
    $runtimePrefix = 'win-'
    $runtimes = @($RuntimeIdentifier | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
    $installerNames = @($runtimes | ForEach-Object {
        "Crypture-$($_.Substring($runtimePrefix.Length))-$version-installer.msi"
    })
    foreach ($name in @($packageName) + $installerNames)
    {
        $output = Join-Path $OutputDirectory $name
        if (Test-Path -LiteralPath $output) { throw "Package already exists: $output" }
    }

    # Use a fresh staging folder so existing artifacts and signed outputs remain intact.
    $stage = Join-Path $StageDirectory ([Guid]::NewGuid().ToString('N'))
    $portableDirectory = Join-Path $stage 'Package'
    $dotnet = (Get-Command dotnet.exe -CommandType Application -ErrorAction Stop).Source
    New-Item -ItemType Directory -Path $stage, $OutputDirectory -Force | Out-Null

    # Restore the latest stable WiX and its matching English installer UI extension.
    $toolsDirectory = Join-Path $PSScriptRoot '.tools'
    $nugetConfig = Join-Path $stage 'NuGet.Config'
    [IO.File]::WriteAllText($nugetConfig, '<configuration><packageSources><clear />' +
        '<add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources></configuration>')
    Invoke-Tool $dotnet @('tool', 'update', 'wix', '--tool-path', $toolsDirectory, '--configfile', $nugetConfig)
    $wix = Join-Path $toolsDirectory 'wix.exe'
    $wixVersion = (Invoke-Tool $wix @('--version')).Trim().Split('+')[0]
    Push-Location $PSScriptRoot
    try
    {
        Invoke-Tool $wix @('extension', 'add', "WixToolset.UI.wixext/$wixVersion")
    }
    finally
    {
        Pop-Location
    }
    $extensionDirectory = Join-Path $PSScriptRoot ".wix\extensions\WixToolset.UI.wixext\$wixVersion"
    $uiExtension = Get-ChildItem -LiteralPath $extensionDirectory -Recurse -Filter 'WixToolset.UI.wixext.dll' |
        Select-Object -First 1 -ExpandProperty FullName
    $licenseRtf = Join-Path $stage 'License.rtf'
    $licenseText = [IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\Code\Data\License - Crypture.txt'))
    $licenseText = $licenseText.Replace('\', '\\').Replace('{', '\{').Replace('}', '\}')
    $licenseText = $licenseText.Replace("`r", '').Replace("`n", '\par ')
    [IO.File]::WriteAllText($licenseRtf, '{\rtf1\ansi{\fonttbl{\f0 Segoe UI;}}\f0\fs18 ' + $licenseText + '}')

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
        if (!$signTool)
        {
            throw 'Install the Windows SDK signing tools, or use -SkipSigning for an unsigned build.'
        }

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
        if (!$signingStore)
        {
            throw 'No trusted, valid code-signing certificate was found. Use -SkipSigning if needed.'
        }
        if ($signingStore -eq 'LocalMachine') { $signOptions += '/sm' }
        $signOptions += @('/sha1', $signingThumbprint)
    }


    foreach ($runtimeId in $runtimes)
    {
        $architecture = $runtimeId.Substring($runtimePrefix.Length)
        $publishDirectory = Join-Path (Join-Path $stage 'Publish') $architecture
        New-Item -ItemType Directory -Path $publishDirectory -Force | Out-Null
        Invoke-Tool $dotnet @('restore', $project, '--runtime', $runtimeId, '--verbosity', 'minimal',
            '-p:SelfContained=true')

        # Embed the runtime and every distributed dependency's license/notice text in About.
        $assetsPath = Join-Path (Split-Path -Parent $project) 'obj\project.assets.json'
        $assets = Get-Content -LiteralPath $assetsPath -Raw | ConvertFrom-Json
        $packageRoot = $assets.packageFolders.PSObject.Properties.Name | Select-Object -First 1
        $notices = Join-Path $stage "RuntimeNotices-$architecture.txt"
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
                    [string] (Invoke-WebRequest -UseBasicParsing -Uri (
                        'https://raw.githubusercontent.com/spdx/license-list-data/main/text/' +
                        "$($license.'#text').txt")).Content
                } else { Get-Content -LiteralPath (Join-Path $packageDirectory $license.'#text') -Raw }))
            }
        }
        foreach ($runtime in @('microsoft.netcore.app.runtime', 'microsoft.windowsdesktop.app.runtime'))
        {
            $runtimeDirectory = Join-Path $packageRoot "$runtime.$runtimeId"
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

        Write-Host "Publishing Crypture $version as an English-only, self-contained $runtimeId EXE."
        Invoke-Tool $dotnet @('publish', $project, '--configuration', 'Release', '--runtime', $runtimeId,
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

        Sign-File $executable

        # Publish the installed application with its runtime and dependencies alongside the executable.
        $installedDirectory = Join-Path (Join-Path $stage 'Installed') $architecture
        Write-Host "Publishing Crypture $version as an unpacked, self-contained $runtimeId application."
        Invoke-Tool $dotnet @('publish', $project, '--configuration', 'Release', '--runtime', $runtimeId,
            '--no-restore', '--verbosity', 'minimal', '-p:PublishProfile=Portable', '-p:PublishSingleFile=false',
            '-p:IncludeNativeLibrariesForSelfExtract=false', '-p:EnableCompressionInSingleFile=false',
            "-p:PublishDir=$installedDirectory/", "-p:RuntimeNoticesFile=$notices")
        $installedConfig = Join-Path $installedDirectory 'Crypture.dll.config'
        Move-Item -LiteralPath $installedConfig -Destination (Join-Path $installedDirectory 'Crypture.exe.config')
        foreach ($file in Get-ChildItem -LiteralPath $installedDirectory -Recurse -File |
            Where-Object { $_.Extension -in @('.exe', '.dll') })
        {
            if ($file.Name -in @('Crypture.exe', 'Crypture.dll') -or
                (!$SkipSigning -and !(Get-AuthenticodeSignature -LiteralPath $file.FullName).SignerCertificate))
            {
                Sign-File $file.FullName
            }
        }

        # Build and validate an MSI containing the unpacked application.
        $installerDirectory = Join-Path (Join-Path $stage 'Installers') $architecture
        $installer = Join-Path $OutputDirectory "Crypture-$architecture-$version-installer.msi"
        Invoke-Tool $wix @('build', (Join-Path $PSScriptRoot 'Crypture.wxs'), '-arch', $architecture,
            '-ext', $uiExtension, '-culture', 'en-us', '-pdbtype', 'none',
            '-intermediatefolder', $installerDirectory, '-out', $installer,
            '-d', "ProductName=$ProductName", '-d', "ProductUrl=$ProductUrl", '-d', "Version=$version",
            '-d', "PublishDirectory=$installedDirectory", '-d', "IconPath=$PSScriptRoot\..\Code\Safe.ico",
            '-d', "LicenseRtf=$licenseRtf",
            '-d', "DialogBitmap=$PSScriptRoot\Artwork\InstallerDialog.png",
            '-d', "BannerBitmap=$PSScriptRoot\Artwork\InstallerBanner.png")
        Invoke-Tool $wix @('msi', 'validate', $installer,
            '-intermediateFolder', (Join-Path $installerDirectory 'Validation'))
        Sign-File $installer
        Write-Host "MSI ready: $installer"

        $binaryOutput = Join-Path $BinaryDirectory $runtimeId
        $packageOutput = Join-Path $portableDirectory $architecture
        New-Item -ItemType Directory -Path $binaryOutput, $packageOutput -Force | Out-Null
        Copy-Item -LiteralPath $executable -Destination (Join-Path $binaryOutput 'Crypture.exe') -Force
        Copy-Item -LiteralPath $executable -Destination (Join-Path $packageOutput 'Crypture.exe')
    }

    # Package only the portable executables in their architecture folders.
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory($portableDirectory, $destination,
        [IO.Compression.CompressionLevel]::Optimal, $false)
    Write-Host "Portable ZIP ready: $destination"
}
catch
{
    Write-Error "Packaging failed: $($_.Exception.Message)" -ErrorAction Continue
    exit 1
}
