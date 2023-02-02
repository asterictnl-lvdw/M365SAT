<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	9-12-2022 10:50
	 Created by:   	Leonardo van de Weteringh
	 Organization: 	Aster ICT
	 Filename:     	moduleduplicatechecker.ps1
	===========================================================================
	.DESCRIPTION
		A description of the file.
#>



<# Check if there are multiple versions installed of a module #>
function Get-DuplicateModules
{
	#Uninstall Modules
	$Modules = @("MicrosoftTeams", "MSOnline", "Az", "AzureADPreview", "ExchangeOnlineManagement", "Microsoft.Online.Sharepoint.PowerShell", "Microsoft.Graph", "Microsoft.Graph.Intune", "PnP.PowerShell")
	Write-Host "Checking all installed modules for multiple versions..."
	ForEach ($CurrentModule in $Modules)
	{
		if ((Get-InstalledModule -Name $CurrentModule -AllVersions).Count -igt 1)
		{
			$GetAllVersions = @(Get-InstalledModule -Name $CurrentModule -AllVersions | Select Version)
			try
			{
				$GalleryModule = Find-Module -Name $CurrentModule -ErrorAction Stop
				if ($PowerShellVersion.Version -igt 2.2.5)
				{
					foreach ($Version in $GetAllVersions)
					{
						if ($Version.Version -ne $GalleryModule.Version)
						{
							Write-Host "Trying to Uninstall version $($version.Version) of $($_.Name)..."
							Uninstall-PSResource -Name $CurrentModule -Version $version.Version -ErrorAction Stop
							Write-Host "Version $($version.Version) of $($CurrentModule) has been removed!" -ForegroundColor Green
						}
					}
				}
				else
				{
					Write-Host "Trying to Uninstall $($CurrentModule)..."
					Get-InstalledModule -Name $CurrentModule -AllVersions | Where-Object { $CurrentModule.Version -ne $GalleryModule.Version } | Uninstall-Module -Force -ErrorAction Stop
					Write-Host "Old versions of $($CurrentModule) have been removed!" -ForegroundColor Green
				}
			}
			catch
			{
				Write-Error "Uninstalling old module $($CurrentModule) failed: $_"
			}
		}
		else
		{
			Write-Warning "Module $($CurrentModule) has no multiple versions!"
		}
	}
	#END SCRIPT
}