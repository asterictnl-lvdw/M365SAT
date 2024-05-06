<# Checks if modules are installed #>
function Check-M365SATModules
{
	Write-Warning "[?] Checking Installed Modules..."
	# Define the set of modules installed and updated from the PowerShell Gallery that we want to maintain
	$Modules = @("MicrosoftTeams", "Az", "ExchangeOnlineManagement", "Microsoft.Online.Sharepoint.PowerShell", "Microsoft.Graph","Microsoft.Graph.Beta","PoShLog")
	#Check which Modules are Installed Already...
	$count = 0
	$installed = Get-InstalledModule
	foreach ($Module in $Modules)
	{
		if ($installed.Name -notcontains $Module)
		{
			Write-Host "`n$Module is not installed." -ForegroundColor Red
			$install = Read-Host -Prompt "Would you like to attempt installation now? (Y|N)"
			if ($install -eq 'y')
			{
				Write-Warning "Trying to install $Module ..."
				Install-Module $Module -Scope CurrentUser -Force -Confirm:$false -AllowClobber
				$count++
			}
		}
		else
		{
			Write-Host "[+] $Module is installed." -ForegroundColor Green
			$count++
		}
	}
	Write-Host "Succesfully Checked all Modules Existence...!"
}