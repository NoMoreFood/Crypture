#requires -Version 5.1
param(
    [string] $BinaryDirectory = "$PSScriptRoot\..\Code\bin\Release\Portable",
    [string] $OutputDirectory = "$PSScriptRoot\..\Binaries",
    [string] $StageDirectory = "$PSScriptRoot\Temp\PackageStage",
    [string] $TimestampUrl = 'http://timestamp.digicert.com',
    [string] $ProductName = 'Crypture',
    [string] $ProductUrl = 'https://github.com/NoMoreFood/Crypture',
    [string] $WixVersion = '7.0.1',
    [string] $SpdxLicenseListVersion = 'v3.29.0',
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
    Invoke-Tool $signTool @('verify', '/pa', '/tw', $Path)
}

function Publish-ReleaseFiles([System.Collections.IDictionary] $Files)
{
    # Replace each file on its destination volume and retain the prior release until publication succeeds.
    $suffix = '.' + [Guid]::NewGuid().ToString('N')
    $published = [Collections.Generic.List[string]]::new()
    try
    {
        foreach ($target in $Files.Keys)
        {
            [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target)) | Out-Null
            [IO.File]::Copy($Files[$target], "$target$suffix.tmp")
            if ([IO.File]::Exists($target))
            {
                [IO.File]::Replace("$target$suffix.tmp", $target, "$target$suffix.bak")
            }
            else { [IO.File]::Move("$target$suffix.tmp", $target) }
            $published.Add($target)
        }
    }
    catch
    {
        $published.Reverse()
        foreach ($target in $published)
        {
            if ([IO.File]::Exists("$target$suffix.bak"))
            {
                [IO.File]::Replace("$target$suffix.bak", $target, [Management.Automation.Language.NullString]::Value)
            }
            else { [IO.File]::Delete($target) }
        }
        throw
    }
    finally
    {
        foreach ($target in $Files.Keys)
        {
            if ([IO.File]::Exists("$target$suffix.tmp")) { [IO.File]::Delete("$target$suffix.tmp") }
        }
    }
    foreach ($target in $published) { [IO.File]::Delete("$target$suffix.bak") }
}

function Write-InstallerConfiguration([string] $ConfigPath, [string] $OutputPath)
{
    # Derive installer properties and XML edits from the distributed configuration.
    [xml] $configuration = Get-Content -LiteralPath $ConfigPath -Raw
    $options = foreach ($node in $configuration.SelectNodes(
        '/configuration/appSettings/add | /configuration/applicationSettings/*/setting | ' +
        '/configuration/userSettings/*/setting'))
    {
        $isAppSetting = $node.Name -eq 'add'
        $name = if ($isAppSetting) { $node.GetAttribute('key') } else { $node.GetAttribute('name') }
        $isXml = !$isAppSetting -and $node.GetAttribute('serializeAs') -eq 'Xml'
        $path = if ($isAppSetting) { "/configuration/appSettings/add[\[]@key='$name'[\]]" }
            else { '/configuration/' + $node.ParentNode.ParentNode.Name + '/' + $node.ParentNode.Name +
                "/setting[\[]@name='$name'[\]]/value" }
        [pscustomobject] @{ Name = $name; Property = 'CRYPTURE_' + $name.ToUpperInvariant();
            Path = $path; IsAppSetting = $isAppSetting; IsXml = $isXml }
    }

    $wixNamespace = 'http://wixtoolset.org/schemas/v4/wxs'
    $utilNamespace = 'http://wixtoolset.org/schemas/v4/wxs/util'
    $settings = [Xml.XmlWriterSettings]::new()
    $settings.Indent = $true
    $settings.IndentChars = '    '
    $settings.NewLineChars = "`r`n"
    $settings.Encoding = [Text.UTF8Encoding]::new($false)
    $writer = [Xml.XmlWriter]::Create($OutputPath, $settings)
    try
    {
        $writer.WriteStartElement('Include', $wixNamespace)
        $writer.WriteAttributeString('xmlns', 'util', $null, $utilNamespace)
        foreach ($option in $options)
        {
            $writer.WriteStartElement('Property', $wixNamespace)
            $writer.WriteAttributeString('Id', $option.Property)
            $writer.WriteAttributeString('Secure', 'yes')
            $writer.WriteEndElement()
        }

        # Retain installed policy during repair and while the upgrade replaces the application.
        $writer.WriteStartElement('ComponentGroup', $wixNamespace)
        $writer.WriteAttributeString('Id', 'CryptureConfigurationComponents')
        $writer.WriteStartElement('Component', $wixNamespace)
        $writer.WriteAttributeString('Id', 'CryptureConfiguration')
        $writer.WriteAttributeString('Directory', 'INSTALLFOLDER')
        $writer.WriteAttributeString('NeverOverwrite', 'yes')
        $writer.WriteStartElement('File', $wixNamespace)
        $writer.WriteAttributeString('Id', 'CryptureConfigurationFile')
        $writer.WriteAttributeString('Source', '$(var.PublishDirectory)\Crypture.exe.config')
        $writer.WriteAttributeString('KeyPath', 'yes')
        $writer.WriteEndElement()
        $writer.WriteEndElement()
        $sequence = 0
        foreach ($option in $options)
        {
            # Reevaluate supplied overrides on repair; the registry marker tracks only the MSI component.
            $writer.WriteStartElement('Component', $wixNamespace)
            $writer.WriteAttributeString('Id', 'Configure_' + $option.Name)
            $writer.WriteAttributeString('Directory', 'INSTALLFOLDER')
            $writer.WriteAttributeString('Condition', $option.Property)
            $writer.WriteAttributeString('Transitive', 'yes')
            $writer.WriteStartElement('RegistryValue', $wixNamespace)
            $writer.WriteAttributeString('Root', 'HKLM')
            $writer.WriteAttributeString('Key', 'Software\Bryan Berns\Crypture\InstallerOverrides')
            $writer.WriteAttributeString('Name', $option.Name)
            $writer.WriteAttributeString('Type', 'integer')
            $writer.WriteAttributeString('Value', '1')
            $writer.WriteAttributeString('KeyPath', 'yes')
            $writer.WriteEndElement()

            # Keep the value element's trailing whitespace for the .NET settings reader.
            $actions = if ($option.IsXml) { @('delete', 'create') } else { @('create') }
            foreach ($action in $actions)
            {
                $writer.WriteStartElement('util', 'XmlConfig', $utilNamespace)
                $writer.WriteAttributeString('Id', $option.Name + '_' + $action)
                $writer.WriteAttributeString('File', '[#CryptureConfigurationFile]')
                $writer.WriteAttributeString('ElementPath', $option.Path)
                $writer.WriteAttributeString('Action', $action)
                $writer.WriteAttributeString('Node', $(if ($option.IsXml -and $action -eq 'create') {
                    'document'
                } elseif ($option.IsXml) { 'element' } else { 'value' }))
                $writer.WriteAttributeString('On', 'install')
                $writer.WriteAttributeString('PreserveModifiedDate', 'yes')
                $writer.WriteAttributeString('Sequence', [string] (++$sequence))
                if ($option.IsAppSetting) { $writer.WriteAttributeString('Name', 'value') }
                if ($action -eq 'create')
                {
                    $writer.WriteAttributeString('Value', '[' + $option.Property + ']')
                }
                else { $writer.WriteAttributeString('VerifyPath', '*') }
                $writer.WriteEndElement()
            }
            $writer.WriteEndElement()
        }
        $writer.WriteEndElement()
        $writer.WriteEndElement()
    }
    finally
    {
        $writer.Dispose()
    }
}

$stage = $null
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
    $unpackedPackageName = "Crypture-$version-unpacked.zip"
    $unpackedDestination = Join-Path $OutputDirectory $unpackedPackageName
    $runtimePrefix = 'win-'
    $runtimes = @($RuntimeIdentifier | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
    # Build in a fresh staging folder before replacing published outputs.
    $stage = Join-Path $StageDirectory ([Guid]::NewGuid().ToString('N'))
    $portableDirectory = Join-Path $stage 'Package'
    $dotnet = (Get-Command dotnet.exe -CommandType Application -ErrorAction Stop).Source
    New-Item -ItemType Directory -Path $stage, $OutputDirectory -Force | Out-Null

    # Restore the pinned WiX release and its matching installer extensions.
    $toolsDirectory = Join-Path $PSScriptRoot '.tools'
    $nugetConfig = Join-Path $stage 'NuGet.Config'
    [IO.File]::WriteAllText($nugetConfig, '<configuration><packageSources><clear />' +
        '<add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources></configuration>')
    Invoke-Tool $dotnet @('tool', 'update', 'wix', '--version', $WixVersion, '--allow-downgrade',
        '--tool-path', $toolsDirectory, '--configfile', $nugetConfig)
    $wix = Join-Path $toolsDirectory 'wix.exe'
    Push-Location $PSScriptRoot
    try
    {
        foreach ($extension in @('UI', 'Util'))
        {
            Invoke-Tool $wix @('extension', 'add', "WixToolset.$extension.wixext/$WixVersion")
        }
    }
    finally
    {
        Pop-Location
    }
    $extensionDirectory = Join-Path $PSScriptRoot ".wix\extensions\WixToolset.UI.wixext\$WixVersion"
    $uiExtension = Get-ChildItem -LiteralPath $extensionDirectory -Recurse -Filter 'WixToolset.UI.wixext.dll' |
        Select-Object -First 1 -ExpandProperty FullName
    $extensionDirectory = Join-Path $PSScriptRoot ".wix\extensions\WixToolset.Util.wixext\$WixVersion"
    $utilExtension = Get-ChildItem -LiteralPath $extensionDirectory -Recurse -Filter 'WixToolset.Util.wixext.dll' |
        Select-Object -First 1 -ExpandProperty FullName
    $licenseRtf = Join-Path $stage 'License.rtf'
    $licenseText = [IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\Code\Data\License - Crypture.txt'))
    $licenseText = $licenseText.Replace('\', '\\').Replace('{', '\{').Replace('}', '\}')
    $licenseText = $licenseText.Replace("`r", '').Replace("`n", '\par ')
    [IO.File]::WriteAllText($licenseRtf, '{\rtf1\ansi{\fonttbl{\f0 Segoe UI;}}\f0\fs18 ' + $licenseText + '}')
    $configurationInclude = Join-Path $stage 'Configuration.wxi'
    Write-InstallerConfiguration (Join-Path $PSScriptRoot '..\Code\App.config') $configurationInclude

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

        $signOptions = @('sign', '/a', '/fd', 'sha256', '/tr', $TimestampUrl, '/td', 'sha256',
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


    $licenseTexts = @{}
    $releaseFiles = [ordered]@{}
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
                # Read each license named by an SPDX expression from the pinned license list release.
                $license = $metadata.license
                $texts.Add("$($library.Name)`r`n" + $(if ($license.type -eq 'expression') {
                    @($license.'#text' -split '\s+(?:AND|OR|WITH)\s+|[()+]' | Where-Object { $_ } |
                        Select-Object -Unique | ForEach-Object {
                            if (!$licenseTexts.ContainsKey($_))
                            {
                                $licenseTexts[$_] = [string] (Invoke-WebRequest -UseBasicParsing -Uri (
                                    'https://raw.githubusercontent.com/spdx/license-list-data/' +
                                    "$SpdxLicenseListVersion/text/$_.txt")).Content
                            }
                            $licenseTexts[$_]
                        }) -join "`r`n`r`n"
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
        Sign-File (Join-Path $installedDirectory 'Crypture.exe')

        # Build and validate an MSI containing the unpacked application.
        $installerDirectory = Join-Path (Join-Path $stage 'Installers') $architecture
        $installerName = "Crypture-$architecture-$version-installer.msi"
        $installer = Join-Path $stage $installerName
        Invoke-Tool $wix @('build', (Join-Path $PSScriptRoot 'Crypture.wxs'), '-arch', $architecture,
            '-ext', $uiExtension, '-ext', $utilExtension, '-culture', 'en-us', '-pdbtype', 'none',
            '-intermediatefolder', $installerDirectory, '-out', $installer,
            '-d', "ProductName=$ProductName", '-d', "ProductUrl=$ProductUrl", '-d', "Version=$version",
            '-d', "PublishDirectory=$installedDirectory", '-d', "IconPath=$PSScriptRoot\..\Code\Safe.ico",
            '-d', "ConfigurationInclude=$configurationInclude",
            '-d', "LicenseRtf=$licenseRtf",
            '-d', "DialogBitmap=$PSScriptRoot\Artwork\InstallerDialog.png",
            '-d', "BannerBitmap=$PSScriptRoot\Artwork\InstallerBanner.png")
        # Same-version upgrades intentionally include the installed version in the removal range.
        Invoke-Tool $wix @('msi', 'validate', $installer, '-sice', 'ICE61',
            '-intermediateFolder', (Join-Path $installerDirectory 'Validation'))
        Sign-File $installer
        $releaseFiles[(Join-Path $OutputDirectory $installerName)] = $installer

        $binaryOutput = Join-Path $BinaryDirectory $runtimeId
        $packageOutput = Join-Path $portableDirectory $architecture
        New-Item -ItemType Directory -Path $packageOutput -Force | Out-Null
        $releaseFiles[(Join-Path $binaryOutput 'Crypture.exe')] = $executable
        Copy-Item -LiteralPath $executable -Destination (Join-Path $packageOutput 'Crypture.exe')
    }

    # Package only the portable executables in their architecture folders.
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $stagedArchive = Join-Path $stage $packageName
    [IO.Compression.ZipFile]::CreateFromDirectory($portableDirectory, $stagedArchive,
        [IO.Compression.CompressionLevel]::Optimal, $false)
    $releaseFiles[$destination] = $stagedArchive

    # Package the unpacked application and its dependencies in architecture folders.
    $unpackedDirectory = Join-Path $stage 'Installed'
    $stagedArchive = Join-Path $stage $unpackedPackageName
    [IO.Compression.ZipFile]::CreateFromDirectory($unpackedDirectory, $stagedArchive,
        [IO.Compression.CompressionLevel]::Optimal, $false)
    $releaseFiles[$unpackedDestination] = $stagedArchive

    # Publish the complete, validated set under an exclusive lock shared by builds to this directory.
    $lock = [IO.FileStream]::new((Join-Path $OutputDirectory '.Crypture-publish.lock'), 'OpenOrCreate',
        'ReadWrite', 'None', 4096, [IO.FileOptions]::DeleteOnClose)
    try { Publish-ReleaseFiles $releaseFiles }
    finally { $lock.Dispose() }
    foreach ($target in $releaseFiles.Keys) { Write-Host "Published $target" }
}
catch
{
    Write-Error "Packaging failed: $($_.Exception.Message)" -ErrorAction Continue
    exit 1
}
finally
{
    if ($stage -and (Test-Path -LiteralPath $stage -PathType Container))
    {
        $run = Get-Item -LiteralPath $stage -Force
        if ($run.Parent.FullName.TrimEnd('\') -ne $StageDirectory.TrimEnd('\') -or
            $run.Name -notmatch '^[0-9a-f]{32}$' -or ($run.Attributes -band [IO.FileAttributes]::ReparsePoint))
        {
            throw "Unexpected build staging directory: $stage"
        }
        Remove-Item -LiteralPath $run.FullName -Recurse -Force
    }
}
