<#	
	.NOTES
	===========================================================================
	 Created with: 	SAPIEN Technologies, Inc., PowerShell Studio 2022 v5.8.213
	 Created on:   	9-12-2022 10:50
	 Created by:   	Leonardo van de Weteringh
	 Organization: 	Aster ICT
	 Version:		3.0
	 Filename:     	moduleduplicatechecker.ps1
	===========================================================================
	.DESCRIPTION
		A description of the file.
#>



<# Check if there are multiple versions installed of a module #>
function Check-M365SATModuleDuplicates
{
	#Uninstall Modules
	$ModuleList = @("MicrosoftTeams", "Az", "ExchangeOnlineManagement", "Microsoft.Online.Sharepoint.PowerShell", "Microsoft.Graph","Microsoft.Graph.Beta","PoShLog")
	
	# Get the new module versions for comparing them to to previous one if updated
	$NewModules = Get-InstalledModule -Name $ModuleList | Select-Object Name, Version | Sort-Object Name
	if ($NewModules)
	{
		Write-Host ("List of updated modules:") -ForegroundColor Green
		$NoUpdatesFound = $true
		foreach ($Module in $NewModules)
		{
			$CurrentVersion = $CurrentModules | Where-Object Name -EQ $Module.Name
			if ($CurrentVersion.Version -notlike $Module.Version)
			{
				$NoUpdatesFound = $false
				Write-Host ("- Updated module {0} from version {1} to {2}" -f $Module.Name, $CurrentVersion.Version, $Module.Version) -ForegroundColor Green
			}
		}
		
		if ($NoUpdatesFound)
		{
			Write-Host ("No modules were updated.") -ForegroundColor Gray
		}
	}
}