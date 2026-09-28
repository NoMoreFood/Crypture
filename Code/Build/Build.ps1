#requires -Version 5.1
param(
    [Parameter(Mandatory = $true)][string] $BinaryDirectory,
    [Parameter(Mandatory = $true)][string] $OutputDirectory,
    [Parameter(Mandatory = $true)][string] $StageDirectory,
    [Parameter(Mandatory = $true)][string] $TimestampUrl,
    [Parameter(Mandatory = $true)][string] $ProductName,
    [Parameter(Mandatory = $true)][string] $ProductUrl
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
    $BinaryDirectory = [IO.Path]::GetFullPath($BinaryDirectory)
    $OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
    $StageDirectory = [IO.Path]::GetFullPath($StageDirectory)
    $executable = Join-Path $BinaryDirectory 'Crypture.exe'

    $assemblyInfo = Get-Content -LiteralPath "$PSScriptRoot\..\Properties\AssemblyInfo.cs" -Raw
    $versionMatch = [regex]::Match($assemblyInfo, 'AssemblyFileVersion\("(\d+\.\d+\.\d+\.\d+)"\)')
    if (!$versionMatch.Success) { throw 'AssemblyFileVersion must contain a four-part release version.' }
    $releaseVersion = [version] $versionMatch.Groups[1].Value
    if ($releaseVersion.Revision -ne 0 -or $releaseVersion.Major -gt 255 -or
        $releaseVersion.Minor -gt 255 -or $releaseVersion.Build -gt 65535)
    {
        throw 'MSI versions require Major.Minor.Build.0, with limits of 255.255.65535.0.'
    }
    $version = $releaseVersion.ToString(3)
    $installerNames = @('x86', 'x64') | ForEach-Object { "Crypture-$_-$version-installer.msi" }
    $portableName = "Crypture-$version-portable.zip"
    $packageNames = @($installerNames) + $portableName
    if (Test-Path -LiteralPath $StageDirectory) { throw 'PackageStage already exists. Move or remove it first.' }
    foreach ($name in $packageNames)
    {
        if (Test-Path -LiteralPath (Join-Path $OutputDirectory $name)) { throw "Package already exists: $name" }
    }

    $msbuild = $null
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path -LiteralPath $vswhere -PathType Leaf)
    {
        $msbuild = Invoke-Tool $vswhere @('-latest', '-products', '*', '-requires', 'Microsoft.Component.MSBuild',
            '-find', 'MSBuild\**\Bin\MSBuild.exe') | Select-Object -First 1
    }
    if (!$msbuild)
    {
        $command = Get-Command MSBuild.exe -CommandType Application -ErrorAction SilentlyContinue
        if ($command) { $msbuild = $command.Source }
    }
    if (!$msbuild)
    {
        throw 'Install Visual Studio or Build Tools with .NET desktop build tools and the .NET 4.8 targeting pack.'
    }

    Write-Host "Restoring packages and rebuilding Crypture $version in Release mode with $msbuild."
    Invoke-Tool $msbuild @("$PSScriptRoot\..\Crypture.csproj", '/nologo', '/verbosity:minimal', '/restore',
        '/t:Rebuild', '/p:Configuration=Release', '/p:Platform=AnyCPU', '/p:RestorePackagesConfig=true',
        "/p:RestoreRepositoryPath=$PSScriptRoot\..\packages",
        "/p:OutputPath=$BinaryDirectory/", "/p:OutDir=$BinaryDirectory/")
    if (!(Test-Path -LiteralPath $executable -PathType Leaf)) { throw 'MSBuild did not produce Crypture.exe.' }
    $binaryVersion = [version] (Get-Item -LiteralPath $executable).VersionInfo.FileVersion
    if ($binaryVersion -ne $releaseVersion) { throw 'The built executable does not match the release version.' }

    $dotnet = (Get-Command dotnet.exe -CommandType Application -ErrorAction Stop).Source
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
    if (!$signTool) { throw 'Install the Windows SDK signing tools before packaging.' }

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
                '1.3.6.1.5.5.7.3.3', $false) | Where-Object {
                $_.HasPrivateKey -and $_.NotBefore -le $now -and $_.NotAfter -gt $now
            })
            if ($certificates.Count -eq 0) { continue }
            $signingStore = $location
            break
        }
        finally
        {
            $certificateStore.Dispose()
        }
    }
    if (!$signingStore)
    {
        throw 'No valid code-signing certificate with a private key was found in either Personal store.'
    }
    if ($signingStore -eq 'LocalMachine') { $signOptions += '/sm' }
    Write-Host "Packaging Crypture $version; SignTool: $signTool; certificate store: $signingStore"

    $toolDirectory = Join-Path $PSScriptRoot '.tools'
    New-Item -ItemType Directory -Path $toolDirectory -Force | Out-Null
    $nugetConfiguration = Join-Path $toolDirectory 'NuGet.Config'
    @'
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources><clear /><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources>
</configuration>
'@ | Set-Content -LiteralPath $nugetConfiguration -Encoding UTF8
    Invoke-Tool $dotnet @('tool', 'update', 'wix', '--tool-path', $toolDirectory,
        '--configfile', $nugetConfiguration, '--no-cache')
    $wix = Join-Path $toolDirectory 'wix.exe'
    $wixVersionOutput = Invoke-Tool $wix @('--version')
    $wixVersion = ([string] $wixVersionOutput).Trim().Split('+')[0]
    if ($wixVersion -notmatch '^\d+\.\d+\.\d+$' -or [version] $wixVersion -lt [version] '7.0.0')
    {
        throw "Expected the latest stable WiX version (7.0 or later), but found $wixVersion."
    }
    Write-Host "Using WiX $wixVersion with matching UI and .NET extensions."

    Push-Location -LiteralPath $PSScriptRoot
    try
    {
        $extensions = @("WixToolset.UI.wixext/$wixVersion", "WixToolset.Netfx.wixext/$wixVersion")
        foreach ($extension in $extensions) { Invoke-Tool $wix @('extension', 'add', $extension) }

        # copy release files to a package staging directory
        New-Item -ItemType Directory -Path $StageDirectory | Out-Null
        Get-ChildItem -LiteralPath $BinaryDirectory -Force | Copy-Item -Destination $StageDirectory -Recurse
        # sign the main executables
        Invoke-Tool $signTool ($signOptions + (Join-Path $StageDirectory 'Crypture.exe'))
        Invoke-Tool $signTool @('verify', '/pa', '/tw', (Join-Path $StageDirectory 'Crypture.exe'))

        # do the build
        foreach ($architecture in @('x86', 'x64'))
        {
            $installer = Join-Path $StageDirectory "Crypture-$architecture-$version-installer.msi"
            Invoke-Tool $wix @('build', "$PSScriptRoot\Crypture.wxs", '-arch', $architecture,
                '-ext', $extensions[0], '-ext', $extensions[1], '-d', "Version=$version",
                '-d', "SourceDir=$PSScriptRoot\..", '-d', "PayloadDir=$StageDirectory", '-bcgg',
                '-pdbtype', 'none', '-out', $installer)
            Invoke-Tool $wix @('msi', 'validate', $installer)
            # sign the msi files
            Invoke-Tool $signTool ($signOptions + $installer)
            Invoke-Tool $signTool @('verify', '/pa', '/tw', $installer)
        }

        $portableDirectory = Join-Path $StageDirectory 'Portable'
        New-Item -ItemType Directory -Path $portableDirectory | Out-Null
        [xml] $installerSource = Get-Content -LiteralPath "$PSScriptRoot\Crypture.wxs" -Raw
        $payloadPrefix = '$(var.PayloadDir)\'
        foreach ($file in $installerSource.SelectNodes("//*[local-name()='File']/@Source"))
        {
            if (!$file.Value.StartsWith($payloadPrefix)) { throw "Unexpected installer payload path: $($file.Value)" }
            $relativePath = $file.Value.Substring($payloadPrefix.Length)
            $destination = Join-Path $portableDirectory $relativePath
            New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
            Copy-Item -LiteralPath (Join-Path $StageDirectory $relativePath) -Destination $destination
        }
        Copy-Item -LiteralPath "$PSScriptRoot\..\LICENSE" -Destination (Join-Path $portableDirectory 'LICENSE.txt')
        @"
Crypture $version Portable

Extract the entire ZIP into a folder, then run Crypture.exe.
Requires Windows with .NET Framework 4.8 or later. No installation is required.
The same package supports x86 and x64 Windows; keep both architecture folders.

Application preferences are stored in your Windows user profile.
Vault access still requires the authorized Windows identity or certificate private key.
Copying a Vault does not transfer local Windows profile or machine protection keys.

The executable is digitally signed. License: LICENSE.txt.
Third-party license information is available in About and DotNet.Notices.txt.
"@ | Set-Content -LiteralPath (Join-Path $portableDirectory 'README.txt') -Encoding UTF8
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::CreateFromDirectory($portableDirectory,
            (Join-Path $StageDirectory $portableName), [IO.Compression.CompressionLevel]::Optimal, $false)
        Write-Host "Created portable package: $portableName"

        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
        foreach ($name in $packageNames)
        {
            [IO.File]::Copy((Join-Path $StageDirectory $name), (Join-Path $OutputDirectory $name), $false)
        }
        Write-Host "Signed installers and the portable ZIP are ready in $OutputDirectory."
    }
    finally
    {
        Pop-Location
    }
}
catch
{
    Write-Error "Packaging failed: $($_.Exception.Message)" -ErrorAction Continue
    exit 1
}
