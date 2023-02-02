# Welcome Script Displays Banner
try
{
	. .\modules\welcome\welcome.ps1
	Banner
}
catch
{
	Write-Error "An error occured!"
}
# Displays if Program is executed with Admin Rights
try
{
	Write-Host "[...] Checking if the script is running as Administrator"
	if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
	{
		Write-Warning "[!] Program needs Administrator Rights! Trying to Run This Program as Administrator..."
		Start-Process PowerShell -Verb RunAs "-NoExit -NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
		exit;
	}
	else
	{
		Write-Host "[+] The script is running as Administrator..." -ForegroundColor Green
	}
}
catch
{
	Write-Error "An error occured!"
}
# Checks if M365SAT has any updates
try
{
	. .\modules\m365satupdater\m365updater.ps1
	Start-M365SATPlusCheck
}
catch
{
	Write-Error "An error occured!"
}
# Checks if all modules are installed and installs them if they are not
try
{
	. .\modules\modulechecker\modulechecker.ps1
	Initialize-M365SATModuleCheckModules
}
catch
{
	Write-Error "An error occured!"
}
# Checks modules for updates
try
{
	. .\modules\moduleupdater\moduleupdater.ps1
	Invoke-M365SATModuleUpdates
}
catch
{
	Write-Error "An error occured!"
}
# Checks for duplicate modules and removes earlier versions
try
{
	. .\modules\moduleduplicatechecker\moduleduplicatechecker.ps1
	Get-DuplicateModules
}
catch
{
	Write-Error "An error occured!"
}
Write-Host "Sucessfully Configured M365SAT. Run Get-M365SATReport to start the audit!" -ForegroundColor Green