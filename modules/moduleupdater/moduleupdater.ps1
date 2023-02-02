<# Check if all modules are up-to-date #>
function Invoke-M365SATModuleUpdates
{
<# Updates all Modules to their latest version #>
	
	#In Case of Powershell TLS v1.2 is not enabled by default. To enable TLS v1.2 connections on .NET Framework we change to Regkeys
	Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
	Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord
	
	# Get all installed modules that have a newer version available
	$Modules = @("MicrosoftTeams", "MSOnline", "Az", "AzureADPreview", "ExchangeOnlineManagement", "Microsoft.Online.Sharepoint.PowerShell", "Microsoft.Graph", "Microsoft.Graph.Intune", "PnP.PowerShell")
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
			$count++
		}
	}
	Write-Host "Checking all installed modules for available updates..."
	$CurrentModules = Get-InstalledModule | Where-Object { $Modules -contains $_.Name }
	
	$CurrentModules | ForEach-Object {
		Write-Host "[>] Checking $($_.Name) ..."
		Try
		{
			$GalleryModule = Find-Module -Name $_.Name -Repository PSGallery -ErrorAction SilentlyContinue #-AllowPreRelease
		}
		Catch
		{
			Write-Error "Module $($_.Name) not found in gallery $_"
			$GalleryModule = $null
			continue
		}
		if ($GalleryModule.Version -gt $_.Version)
		{
			Write-Host "$($_.Name) will be updated. Galleryversion: $($GalleryModule.Version), Localversion $($_.Version)"
			try
			{
				Update-Module $_.Name -ErrorAction SilentlyContinue -Force
				Write-Host "$($_.Name)  has been updated!" -ForegroundColor Green
			}
			Catch
			{
				Write-Error "$($_.Name) failed: $_ "
				continue
				
			}
		}
		elseif (($null -ne $GalleryModule) -or ($GalleryModule.Version -le $_.Version))
		{
			Write-Warning "$($_.Name) is up to date!"
		}
	}
}