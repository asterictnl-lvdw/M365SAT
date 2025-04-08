<#	
    .NOTES
    ===========================================================================
     Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
     Created on:   	9-12-2022 10:50
     Updated on:	5-3-2025 16:24
     Created by:   	Leonardo van de Weteringh
     Organization: 	Karmakstylez
     Version:		5.0
     Filename:     	Check-M365SATModuleDuplicates.ps1
    ===========================================================================
    .DESCRIPTION
        Makes sure the old versions are uninstalled of the modules. Always execute this script AFTER you have done the updates and do not do it BEFORE as it might happen that you have to install all the modules again!
#>

function Check-M365SATModuleDuplicates {
    <#
        .SYNOPSIS
        Removes older versions of specified PowerShell modules, leaving only the latest version installed.

        .DESCRIPTION
        This function checks for multiple versions of specified modules and uninstalls older versions.
        It ensures that the latest version is preserved and skips modules that are not installed or have only one version.

        .NOTES
        - Always run this script AFTER updating modules.
        - Ensure you have administrative privileges if required.
    #>
    # List of modules to check for duplicates
    $ModuleList = @("MicrosoftTeams", "Az", "ExchangeOnlineManagement", "Microsoft.Online.Sharepoint.PowerShell", "Microsoft.Graph", "Microsoft.Graph.Beta", "PoShLog", "PnP.PowerShell")

    foreach ($Module in $ModuleList) {
        Write-Host "Checking module: $Module" -ForegroundColor Cyan

        # Get the latest available version of the module from the online repository
        try {
            $LatestVersion = Find-Module -Name $Module -ErrorAction Stop | Sort-Object Version -Descending | Select-Object -First 1
			Write-Host "$Module has $($LatestVersion.Version) with $($LatestVersion.PublishedDate)"
        } catch {
            Write-Warning "Module '$Module' not found in the online repository. Skipping..."
            continue
        }

        # Get all locally installed versions of the module
        $InstalledVersions = Get-Module -ListAvailable -Name $Module -ErrorAction SilentlyContinue | Sort-Object Version -Descending

        if (-not $InstalledVersions) {
            Write-Host "Module '$Module' is not installed locally. Skipping..." -ForegroundColor Yellow
            continue
        }

        # Get the latest installed version
        $LatestInstalledVersion = $InstalledVersions | Select-Object -First 1

        # Compare the latest installed version with the latest available version
        if ($LatestInstalledVersion.Version -lt $LatestVersion.Version) {
            Write-Warning "The latest installed version of '$Module' ($($LatestInstalledVersion.Version)) is outdated compared to the online version ($($LatestVersion.Version))."
        }

        # If there is only one installed version, skip removal
        if ($InstalledVersions.Count -le 1) {
            Write-Host "Only one version of '$Module' is installed ($($LatestInstalledVersion.Version)). Skipping removal." -ForegroundColor Green
            continue
        }

        # Uninstall older versions
        foreach ($Version in $InstalledVersions) {
            if ($Version.Version -ne $LatestInstalledVersion.Version) {
                Write-Host "Uninstalling older version $($Version.Version) of '$Module'..." -ForegroundColor Yellow
                try {
                    Uninstall-Module -Name $Module -RequiredVersion $Version.Version -Force -ErrorAction Stop
                    Write-Host "Successfully uninstalled version $($Version.Version) of '$Module'." -ForegroundColor Green
                } catch {
                    Write-Warning "Failed to uninstall version $($Version.Version) of '$Module'."
                    Write-Warning "Please manually uninstall using: Uninstall-Module -Name $Module -RequiredVersion $($Version.Version) -Force"
                }
            }
        }
    }
}