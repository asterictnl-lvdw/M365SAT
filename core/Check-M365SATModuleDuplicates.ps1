<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	9-12-2022 10:50
	 Updated on:	26-7-2024 10:58
	 Created by:   	Leonardo van de Weteringh
	 Organization: 	Aster ICT
	 Version:		4.0
	 Filename:     	moduleduplicatechecker.ps1
	===========================================================================
	.DESCRIPTION
		Makes sure the old versions are uninstalled of the modules. Always execute this script AFTER you have done the updates and do not do it BEFORE as it might happen that you have to install all the modules again!
#>


<# Check if there are multiple versions installed of a module #>
function Check-M365SATModuleDuplicates
{
	#Uninstall Modules
	$ModuleList = @("MicrosoftTeams", "Az", "ExchangeOnlineManagement", "Microsoft.Online.Sharepoint.PowerShell", "Microsoft.Graph","Microsoft.Graph.Beta","PoShLog")
	
	# Get the new module versions for comparing them to to previous one if updated
	foreach ($Module in $ModuleList){
		# First you get the online latest version available
		$LatestVersion = Find-Module -Name $Module | Sort-Object Version -Descending | Select-Object Version -First 1
		$stronlver = $LatestVersion | Select-Object @{n='OnlineVersion'; e={$_.Version -as [string]}}
		$b = $stronlver | Select-Object OnlineVersion -ExpandProperty OnlineVersion
		$charCount = ($a.ToCharArray() | Where-Object {$_ -eq '.'} | Measure-Object).Count

		# Second you get the local version and filter all 
		$InstalledVersion = (Get-Module -ListAvailable -Name $Module | Sort-Object Version -Descending | Select-Object Version -First 1) # Latest version
		$strlocver = $InstalledVersion | Select-Object @{n='ModuleVersion'; e={$_.Version -as [string]}}
		$a = $strlocver | Select-Object ModuleVersion -ExpandProperty ModuleVersion

		# Gather only the old version as it removes the versions that are not equal to the latest version
		$OldVersions = (Get-Module -ListAvailable -Name $Module | Select-Object Version | Where-Object {$InstalledVersion -ne $LatestVersion})
		foreach ($OldVersion in $OldVersions){
			Write-Host "Uninstalling Version $OldVersion from $Module..."
			try{
				Uninstall-Module -Name $Module -RequiredVersion $OldVersion -Force
			}catch{
				Write-Warning "Error uninstalling $OldVersion from $Module!"
				Write-Warning "Please close PowerShell and open it again and remove the version by utilizing this command:"
				Write-Warning "Uninstall-Module -Name $Module -RequiredVersion $OldVersion -Force"
			}
			
		}
	}
}