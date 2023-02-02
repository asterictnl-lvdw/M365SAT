<# Checks if modules are installed #>
function Initialize-M365SATModuleCheckModules
{
	Write-Warning "[?] Checking Installed Modules..."
	# Define the set of modules installed and updated from the PowerShell Gallery that we want to maintain
	$O365Modules = @("MicrosoftTeams", "MSOnline", "Az", "AzureADPreview", "ExchangeOnlineManagement", "Microsoft.Online.Sharepoint.PowerShell", "Microsoft.Graph", "Microsoft.Graph.Intune", "PnP.PowerShell")
	#Check which Modules are Installed Already...
	$installed = Get-InstalledModule
	foreach ($module in $O365Modules)
	{
		if ($installed.Name -notcontains $module)
		{
			Write-Host "`n$module is not installed." -ForegroundColor Red
			$install = Read-Host -Prompt "Would you like to attempt installation now? (Y|N)"
			if ($install -eq 'y')
			{
				Install-Module $module -Scope CurrentUser -Force -Confirm:$false -AllowClobber
				$count++
			}
		}
		else
		{
			Write-Host "[+] $module is installed." -ForegroundColor Green
			$count++
		}
	}
}