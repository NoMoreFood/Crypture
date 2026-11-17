#requires -Version 5.1
#requires -RunAsAdministrator
param(
    [Parameter(Mandatory)][string] $PreviousInstallerPath,
    [Parameter(Mandatory)][string] $InstallerPath,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string] $ExpectedAssemblyHash,
    [string] $ExpectedConfigPath = "$PSScriptRoot\..\Code\App.config",
    [string] $TestDirectory = (Join-Path ([IO.Path]::GetTempPath()) ('Crypture.Installer-' + [Guid]::NewGuid()))
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PreviousInstallerPath = (Resolve-Path -LiteralPath $PreviousInstallerPath).Path
$InstallerPath = (Resolve-Path -LiteralPath $InstallerPath).Path
$ExpectedConfigPath = (Resolve-Path -LiteralPath $ExpectedConfigPath).Path
$TestDirectory = [IO.Path]::GetFullPath($TestDirectory)

# Run only on an isolated machine; never replace an existing installation or its policy.
$installed = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
    Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -eq 'Crypture' }
if ($installed) { throw 'Uninstall Crypture from the test machine before running installer upgrade checks.' }
if (Test-Path -LiteralPath $TestDirectory) { throw 'Choose an unused test directory.' }
New-Item -ItemType Directory -Path $TestDirectory | Out-Null
$installDirectory = Join-Path $TestDirectory 'Installed'
$configPath = Join-Path $installDirectory 'Crypture.exe.config'
$activeInstaller = $null
$checks = 0

function Invoke-Installer([string] $Name, [string[]] $Arguments)
{
    $log = Join-Path $TestDirectory ($Name + '.log')
    $process = Start-Process msiexec.exe -ArgumentList ($Arguments + @('/qn', '/norestart', '/l*v', "`"$log`"")) `
        -WindowStyle Hidden -PassThru -Wait
    if ($process.ExitCode -notin 0, 3010) { throw "$Name failed with exit code $($process.ExitCode). See $log." }
}

function Assert-Configuration([xml] $Expected, [string] $Name)
{
    # Compare the entire XML tree, including unknown administrator settings, without indentation differences.
    [xml] $actual = Get-Content -LiteralPath $configPath -Raw
    [xml] $normalized = $Expected.OuterXml
    if ($actual.DocumentElement.OuterXml -cne $normalized.DocumentElement.OuterXml)
    {
        $actual.Save((Join-Path $TestDirectory ($Name + '-actual.config')))
        $Expected.Save((Join-Path $TestDirectory ($Name + '-expected.config')))
        throw "$Name changed unexpected configuration values. See $TestDirectory."
    }
    $script:checks++
    Write-Output "PASS: $Name"
}

try
{
    # Carry installer properties and later administrator edits through an actual major upgrade.
    $activeInstaller = $PreviousInstallerPath
    Invoke-Installer 'InstallPrevious' @('/i', "`"$PreviousInstallerPath`"",
        "INSTALLFOLDER=`"$installDirectory`"", 'CRYPTURE_RECOVERYPROTECTIONDESCRIPTOR=LOCAL=machine',
        'CRYPTURE_CLIPBOARDTIMEOUTSECONDS=60')
    $policy = New-Object Xml.XmlDocument
    $policy.PreserveWhitespace = $true
    $policy.Load($configPath)
    $policy.SelectSingleNode("/configuration/appSettings/add[@key='ClipboardTimeoutSeconds']").value = '45'
    $message = $policy.SelectSingleNode(
        "/configuration/applicationSettings/*/setting[@name='StartupMessageText']/value")
    $message.InnerText = 'Policy & <review>'
    $extra = $policy.CreateElement('add')
    $extra.SetAttribute('key', 'AdministratorSetting')
    $extra.SetAttribute('value', 'Retain this value')
    $null = $policy.configuration.appSettings.AppendChild($extra)
    $policy.Save($configPath)
    Copy-Item -LiteralPath $configPath -Destination (Join-Path $TestDirectory 'Policy.config')
    $hash = (Get-FileHash -LiteralPath $configPath).Hash
    Invoke-Installer 'Upgrade' @('/i', "`"$InstallerPath`"")
    $activeInstaller = $InstallerPath
    if ((Get-FileHash -LiteralPath (Join-Path $installDirectory 'Crypture.dll')).Hash -ne $ExpectedAssemblyHash)
    {
        throw 'Upgrade retained an older application assembly.'
    }
    $checks++
    Write-Output 'PASS: Upgrade installs the new application assembly'
    foreach ($mode in @('', 'omus', 'amus'))
    {
        if ($mode) { Invoke-Installer "Repair-$mode" @("/f$mode", "`"$InstallerPath`"") }
        if ((Get-FileHash -LiteralPath $configPath).Hash -cne $hash)
        {
            throw "Upgrade or repair ($mode) rewrote the installed policy."
        }
        Assert-Configuration $policy "PreservePolicy-$mode"
    }

    # Supplied overrides affect only their own values; false and empty collections are explicit values.
    Invoke-Installer 'Override' @('/i', "`"$InstallerPath`"", 'REINSTALL=ALL', 'REINSTALLMODE=amus',
        'CRYPTURE_CLIPBOARDTIMEOUTSECONDS=90', 'CRYPTURE_ENABLEFIDOPROTECTION=False',
        'CRYPTURE_RECENTVAULTS="<ArrayOfString />"')
    $policy.SelectSingleNode("/configuration/appSettings/add[@key='ClipboardTimeoutSeconds']").value = '90'
    $fido = $policy.SelectSingleNode(
        "/configuration/applicationSettings/*/setting[@name='EnableFidoProtection']/value")
    $fido.InnerText = 'False'
    $policy.SelectSingleNode("/configuration/userSettings/*/setting[@name='RecentVaults']/value").InnerXml =
        '<ArrayOfString />'
    Assert-Configuration $policy 'ApplyOnlyExplicitOverrides'
    Copy-Item -LiteralPath $configPath -Destination (Join-Path $TestDirectory 'Override.config')
    Invoke-Installer 'RepairOverrides' @('/fomus', "`"$InstallerPath`"")
    Assert-Configuration $policy 'RetainExplicitOverridesOnRepair'

    # MSI treats empty properties as absent; whitespace explicitly clears the trimmed recovery policy.
    Invoke-Installer 'ClearRecovery' @('/i', "`"$InstallerPath`"", 'REINSTALL=ALL', 'REINSTALLMODE=omus',
        'CRYPTURE_RECOVERYPROTECTIONDESCRIPTOR=" "')
    $policy.SelectSingleNode("/configuration/appSettings/add[@key='RecoveryProtectionDescriptor']").value = ' '
    Assert-Configuration $policy 'ClearRecoveryOnlyWhenRequested'

    Invoke-Installer 'UninstallUpgrade' @('/x', "`"$InstallerPath`"")
    $activeInstaller = $null
    if (Test-Path -LiteralPath $configPath) { throw 'Uninstall retained the configuration file.' }
    $checks++
    Write-Output 'PASS: Uninstall removes the configuration file'

    # A clean installation still gets every distributed default without MSI property overrides.
    $activeInstaller = $InstallerPath
    Invoke-Installer 'InstallFresh' @('/i', "`"$InstallerPath`"", "INSTALLFOLDER=`"$installDirectory`"")
    Assert-Configuration ([xml](Get-Content -LiteralPath $ExpectedConfigPath -Raw)) 'FreshDefaults'
    Copy-Item -LiteralPath $configPath -Destination (Join-Path $TestDirectory 'Fresh.config')
    Write-Output "Passed $checks installer upgrade checks. Evidence: $TestDirectory"
}
finally
{
    if ($activeInstaller) { Invoke-Installer 'Cleanup' @('/x', "`"$activeInstaller`"") }
}
