#Requires -Version 5.1
function ExecuteM365SAT
{
	Import-Module .\M365SAT.psd1
	#Get-M365SATReport -OutPath "C:\Out" -Username "example@example.org" -EnvironmentType AZURE,M365 -BenchmarkVersion "Latest" -Modules "All" -LicenseMode "All" -LicenseLevel "All" -reportType "HTML" -AllowLogging "Warning" -LocalMode -SkipChecks
	Get-M365SATReport -OutPath "C:\Out" -Username "example@example.org" -EnvironmentType M365 -BenchmarkVersion "Latest" -Modules "All" -LicenseMode "E3" -LicenseLevel "All" -reportType "HTML" -AllowLogging "Warning" -LocalMode -SkipChecks
	#Get-M365SATReport -OutPath "C:\Out" -Username "example@example.org" -EnvironmentType M365 -BenchmarkVersion "Latest" -Modules Exchange,Azure -LicenseMode "E3" -LicenseLevel "All" -reportType "HTML" -AllowLogging "Warning" -LocalMode -SkipChecks
	Remove-Module M365SAT -Force
}

#The script is being designed to work with PowerShell 5.1 where there is no automatic detection of the operating system. For PowerShell 7 $IsLinux $IsWindows can be used.
function CheckAdminPrivBeta
{
	# Check if script is running as Adminstrator and if not use RunAs
	if ($OS -eq 'Windows'){
		Write-Host "[...] Checking if the script is running as Administrator"
		$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
		if (-not $IsAdmin)
		{
			Write-Warning "[!] Program needs Administrator Rights! Trying to Elevate to Admin..."
			Start-Process powershell -Verb runas -ArgumentList "-NoExit -c cd '$pwd'; .\M365SATTester.ps1"
		}
		else
		{
			Write-Host "[+] The script is running as Administrator..." -ForegroundColor Green
			ExecuteM365SAT
		}
	}elseif($OS -eq 'Linux'){
		ExecuteM365SAT
	}elseif($OS -eq 'MacOSX'){
		ExecuteM365SAT
	}

}

function Get-OperatingSystem{
	param
	(
		[Parameter(Mandatory = $true,
			HelpMessage = 'Operating System: Windows / Linux / MacOSX')]
		[ValidateSet('Windows', 'Linux', 'MacOSX', IgnoreCase = $true)]
		[string]$OS = 'Windows'
	)
	CheckAdminPrivBeta
}
if ($args[1] -eq $null){
	Get-OperatingSystem
}
else
{
	Get-OperatingSystem $args[1]
}
