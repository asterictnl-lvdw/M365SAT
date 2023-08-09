function ExecuteM365SAT
{
	Import-Module .\M365SAT.psd1
	Get-M365SATReport -OutPath "C:\Out" -SkipChecks -Username "example@contoso.com" -reportType "HTML" -AllowLogging "Warning" -UseCustomModules
	Remove-Module M365SAT
}


function CheckAdminPrivBeta
{
	# Check if script is running as Adminstrator and if not use RunAs
	Write-Host "[...] Checking if the script is running as Administrator"
	$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
	if (-not $IsAdmin)
	{
		Write-Warning "[!] Program needs Administrator Rights! Please elevate PowerShell and try again..."
	}
	else
	{
		Write-Host "[+] The script is running as Administrator..." -ForegroundColor Green
		ExecuteM365SAT
	}
}
CheckAdminPrivBeta