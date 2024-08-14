<# Check if all modules are up-to-date #>
function Update-M365SATModules
{
<# Updates all Modules to their latest version #>
	
	#In Case of Powershell TLS v1.2 is not enabled by default. To enable TLS v1.2 connections on .NET Framework we change to Regkeys
	Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
	Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
	$ModuleList = @("MicrosoftTeams", "Az", "ExchangeOnlineManagement", "Microsoft.Online.Sharepoint.PowerShell", "Microsoft.Graph","Microsoft.Graph.Beta")

	# Set PSGallery to trusted repository if needed!
	$Policy = Get-PSRepository -Name "PSGallery" | Select-Object -Property -InstallationPolicy
	if ($($Policy.InstallationPolicy) -ne "Trusted") {
		Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
		Write-Information -MessageData "Setting PSGallery repository to trusted."
	}
	
	foreach ($Module in $ModuleList){
		$InstalledVersion = (Get-Module -ListAvailable -Name $Module | Sort-Object Version -Descending | Select-Object Version -First 1)
		$strlocver = $InstalledVersion | Select-Object @{n='ModuleVersion'; e={$_.Version -as [string]}}
		$a = $strlocver | Select-Object ModuleVersion -ExpandProperty ModuleVersion
		$LatestVersion = Find-Module -Name $Module | Sort-Object Version -Descending | Select-Object Version -First 1
		$stronlver = $LatestVersion | Select-Object @{n='OnlineVersion'; e={$_.Version -as [string]}}
		$b = $stronlver | Select-Object OnlineVersion -ExpandProperty OnlineVersion
		$charCount = ($a.ToCharArray() | Where-Object {$_ -eq '.'} | Measure-Object).Count
		# Version comparison now possible in PowerShell
		if ([version]"$a" -ge [version]"$b") {
			Write-Host "Module: $Module"
			Write-Host "Installed version: $a is up-to-date!"
		  }
		  else {
			Write-Host "Module: $Module"
				Write-Host "Installed Module:$a is lower version than $b"
				#ask for update  
				do { $askyesno = (Read-Host "Do you want to update Module $Module (Y/N)").ToLower() } while ($askyesno -notin @('y','n'))
					  if ($askyesno -eq 'y') {
						  Write-Host "Selected YES Updating module $Module"
						  Update-Module -Name $Module -Verbose -Force
						  
						  } else {
						  Write-Host "Selected NO , no updates to Module $Module were done"
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


