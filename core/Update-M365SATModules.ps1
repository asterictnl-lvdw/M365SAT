<# Check if all modules are up-to-date #>
function Update-M365SATModules
{
<# Updates all Modules to their latest version #>
	
	#In Case of Powershell TLS v1.2 is not enabled by default. To enable TLS v1.2 connections on .NET Framework we change to Regkeys
	Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
	Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
	$ModuleList = @("MicrosoftTeams", "Az", "ExchangeOnlineManagement", "Microsoft.Online.Sharepoint.PowerShell", "Microsoft.Graph","Microsoft.Graph.Beta")
	# Get all neccessary modules
	Write-Host ("Retrieving all installed modules ...") -ForegroundColor Green
	$CurrentModules = Get-InstalledModule -Name $ModuleList | Select-Object Name, Version | Sort-Object Name
	if (-not $CurrentModules)
	{
		Write-Host ("No modules found.") -ForegroundColor Gray
		return
	}
	else
	{
		$ModulesCount = $CurrentModules.Count
		$DigitsLength = $ModulesCount.ToString().Length
		Write-Host ("{0} modules found." -f $ModulesCount) -ForegroundColor Gray
	}
	
	Write-Host ("Updating installed modules to the latest Production version ...") -ForegroundColor Green
	
	
	# Loop through the installed modules and update them if a newer version is available
	$i = 0
	foreach ($Module in $CurrentModules)
	{
		$i++
		$Counter = ("[{0,$DigitsLength}/{1,$DigitsLength}]" -f $i, $ModulesCount)
		$CounterLength = $Counter.Length
		Write-Host ('{0} Checking for updated version of module {1} ...' -f $Counter, $Module.Name) -ForegroundColor Green
		try
		{
			Update-Module -Name $Module.Name -AcceptLicense -Scope:AllUsers -ErrorAction Stop
		}
		catch
		{
			Write-Host ("{0$CounterLength} Error updating module {1}!" -f ' ', $Module.Name) -ForegroundColor Red
		}
		
		# Retrieve newest version number and remove old(er) version(s) if any
		$AllVersions = Get-InstalledModule -Name $Module.Name -AllVersions | Sort-Object PublishedDate -Descending
		$MostRecentVersion = $AllVersions[0].Version
		if ($AllVersions.Count -gt 1)
		{
			Foreach ($Version in $AllVersions)
			{
				if ($Version.Version -ne $MostRecentVersion)
				{
					try
					{
						Write-Host ("{0,$CounterLength} Uninstalling previous version {1} of module {2} ..." -f ' ', $Version.Version, $Module.Name) -ForegroundColor Gray
						Uninstall-Module -Name $Module.Name -RequiredVersion $Version.Version -Force:$True -ErrorAction Stop
					}
					catch
					{
						Write-Warning ("{0,$CounterLength} Error uninstalling previous version {1} of module {2}!" -f ' ', $Version.Version, $Module.Name)
					}
				}
			}
		}
	}
}


function PowerShellGetVersion
{
	# For brand new users PowerShellGetVersion can be updated as it is recommended to update it to v2.x.x or later
	$PowerShellGetVersion = Get-InstalledModule -Name "PowerShellGet" -ErrorAction SilentlyContinue
	if ($PowerShellGetVersion.Name -notcontains "PowerShellGet")
	{
		Write-Host "`nPowerShellGet V2 is not installed." -ForegroundColor Red
		$install = Read-Host -Prompt "Would you like to attempt installation now? (Y|N)"
		if ($install -eq 'y')
		{
			Write-Host "Installing NuGet First..."
			Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
			Write-Host "Installing PowerShellGet..."
			Install-Module "PowerShellGet" -Scope CurrentUser -Force -Confirm:$false -AllowClobber | Out-Null
		}
	}
}


