#requires -Version 7.0
#requires -PSEdition Core
param(
    [string] $ConfigPath = "$env:ProgramFiles\Crypture\Crypture.exe.config",
    [string] $ExpectedConfigPath = "$PSScriptRoot\..\Code\App.config"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Configuration

# Read the installed file through the same configuration parser used by the application.
$map = [System.Configuration.ExeConfigurationFileMap]::new()
$map.ExeConfigFilename = (Resolve-Path -LiteralPath $ConfigPath).Path
$actual = [System.Configuration.ConfigurationManager]::OpenMappedExeConfiguration($map, 'None')
[xml] $expected = Get-Content -LiteralPath $ExpectedConfigPath -Raw
$checks = 0
foreach ($option in $expected.configuration.appSettings.add)
{
    if ($actual.AppSettings.Settings[$option.key].Value -cne $option.value)
    {
        throw "Installed app setting does not match: $($option.key)"
    }
    $checks++
}

$serializer = [Xml.Serialization.XmlSerializer]::new([Collections.Specialized.StringCollection])
foreach ($group in @('applicationSettings', 'userSettings'))
{
    $section = $actual.GetSection("$group/Crypture.Properties.Settings")
    $options = $expected.SelectNodes("/configuration/$group/Crypture.Properties.Settings/setting")
    if ($section.Settings.Count -ne $options.Count) { throw "Installed setting count does not match: $group" }
    foreach ($option in $options)
    {
        $setting = $section.Settings.Get($option.name)
        if (!$setting -or $setting.SerializeAs.ToString() -cne $option.serializeAs)
        {
            throw "Installed setting is missing or has the wrong serialization: $($option.name)"
        }
        if ($option.serializeAs -eq 'Xml')
        {
            # Deserialize both collections to check their values and ordering, independent of XML formatting.
            $collections = foreach ($value in @($option.SelectSingleNode('value'), $setting.Value.ValueXml))
            {
                [xml] $document = $value.InnerXml
                $reader = [Xml.XmlNodeReader]::new($document)
                try
                {
                    [string[]] $items = $serializer.Deserialize($reader)
                    $items.Count.ToString() + ':' + [string]::Join([char]0, $items)
                }
                finally { $reader.Dispose() }
            }
            if ($collections[0] -cne $collections[1]) { throw "Installed collection does not match: $($option.name)" }
        }
        elseif ($setting.Value.ValueXml.InnerText -cne $option.SelectSingleNode('value').InnerText)
        {
            throw "Installed setting does not match: $($option.name)"
        }
        $checks++
    }
}
Write-Output "Passed $checks installed configuration checks."
