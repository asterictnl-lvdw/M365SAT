#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
	.SYNOPSIS
		M365SAT - The Microsoft 365 Security Assessment Tool
    
    .VERSION
        Version 3.0 Alpha

    .RELEASE_DATE
        08-23-2024

	.DESCRIPTION
       Allows an Administrator to audit Microsoft 365 environments by executing various 'inspector'
       modules and generates a report afterwards with the eventual findings.

	.NOTES
		Leonardo van de Weteringh
		Cyber Security Specialist
        support@basicallysecure.nl

        Output report uses open source components for HTML formatting
        - Bootstrap 5 - MIT License - https://getbootstrap.com/docs/4.0/about/license/
        - Fontawesome 6 - CC BY 4.0 License - https://fontawesome.com/license/free
        - Leonardo van de Weteringh © 2024
        
        ############################################################################

        URL: https://github.com/asterictnl-lvdw/M365SAT

        ############################################################################    

	.LINK
        https://github.com/asterictnl-lvdw/M365SAT

#>

<# Sets Directory M365SAT #>
function Get-M365SATDirectory
{
<#Gets or creates the M365SAT directory in AppData#>
	
	If ($IsWindows)
	{
		$Directory = "$($env:LOCALAPPDATA)\Microsoft\M365SAT"
	}
	elseif ($IsLinux -or $IsMac)
	{
		$Directory = "$($env:HOME)/M365SAT"
	}
	else
	{
		$Directory = "$($env:LOCALAPPDATA)\Microsoft\M365SAT"
	}
	
	If (Test-Path $Directory)
	{
		Return $Directory
	}
	else
	{
		mkdir $Directory | Out-Null
		Return $Directory
	}
}

<# Cleans temporary files #>
function Invoke-M365SATCleanup
{
<# Ensures removal of temporary files that are created by 365Inspect+ #>
	foreach ($file in $tempfiles)
	{
		Remove-Item $file -Force
	}
}

function Get-M365SATReport
{
	param
	(
		[Parameter(Mandatory = $false,
			HelpMessage= 'Environment Type: Default/USGovGCCHigh/USGovDoD/Germany/China')]
		[ValidateSet('Default', 'USGovGCCHigh', 'USGovDoD', 'Germany', 'China', IgnoreCase = $True)]
		[string]$Environment = 'Default',
		[Parameter(Mandatory = $true,
			HelpMessage = 'The location to export the Report, e.g. C:\out')]
		[string]$OutPath,
		[Parameter(Mandatory = $true,
			HelpMessage = 'Enter the Administrator Username:')]
		[string]$Username,
		[Parameter(Mandatory = $false,
			HelpMessage = 'Enter the Administrator Password:')]
		[SecureString]$Password,
		[Parameter(Mandatory = $true,
			HelpMessage = 'Choose Environment to Audit: M365 / AZURE / CUSTOM / ALL')]
		[ValidateSet('M365', 'AZURE', 'CUSTOM', 'ALL', IgnoreCase = $true)]
		[string[]]$EnvironmentType = "ALL",
		[Parameter(Mandatory = $true,
			HelpMessage = 'Choose Benchmark Version: 3 / 2 / LATEST')]
		[ValidateSet(3, 2, 'LATEST', IgnoreCase = $true)]
		[string]$BenchmarkVersion = "LATEST",
		[Parameter(Mandatory = $true,
			HelpMessage = 'Available Modules: Azure / Exchange / Office365 / Sharepoint / Teams / All')]
		[ValidateSet('Azure', 'Exchange', 'Office365', 'Sharepoint', 'Teams', 'All', IgnoreCase = $true)]
		[String[]]$Modules = "All",
		[Parameter(Mandatory = $false,
			HelpMessage = 'Choose Benchmark License Mode: E3 / E5 / All')]
		[ValidateSet("E3", "E5", 'All', IgnoreCase = $true)]
		[string]$LicenseMode = "All",
		[Parameter(Mandatory = $false,
			HelpMessage = 'Choose Benchmark Level: L1 / L2 / All')]
		[ValidateSet("L1", "L2", 'All', IgnoreCase = $true)]
		[string]$LicenseLevel = "All",
		[Parameter(Mandatory = $true,
			HelpMessage = 'Choose the Report Format.  HTML / CSV / XML / CSMS')]
		[ValidateSet('HTML', 'CSV', 'XML', 'CSMS', IgnoreCase = $true)]
		[string]$reportType = "HTML",
		[Parameter(Mandatory = $false,
			HelpMessage = 'Log Message Level: Verbose / Debug / Info / Warning / Error / Fatal')]
		[ValidateSet('Verbose', 'Debug', 'Info', 'Warning', 'Error', 'Fatal', IgnoreCase = $true)]
		[string]$AllowLogging = "Warning",
		[Parameter(Mandatory = $false,
			HelpMessage = 'Skips Module Updates (Experimental)')]
		[switch]$SkipChecks,
		[Parameter(Mandatory = $false,
			HelpMessage = 'Use the Expirimental MultiThreaded Scanner (Not Recommended!)')]
		[switch]$ExpirimentalMode,
		[switch]$LocalMode,
		[switch]$SkipLogin
	)
	
	# Variables
	$tempfiles = @()
	$MaximumFunctionCount = 32768
	$RootDirectory = "$PSScriptRoot"
	$Directory = "$PSScriptRoot\inspectors"
	$DateNow = (Get-Date -Format hhmm-ddMMyyyy)
	
	# Import Variables that do not have dependencies
	
	# Displays Banner
	. $PSScriptRoot\modules\welcome\Invoke-M365SATBanner.ps1
	
	# Initializes Logger
	. $PSScriptRoot\core\Invoke-M365SATLogger.ps1
	
	# Connection Modules
	. $PSScriptRoot\core\Connect-M365SAT.ps1
	. $PSScriptRoot\core\Disconnect-M365SAT.ps1
	
	# Get & Run Checks
	. $PSScriptRoot\core\Invoke-M365SATChecks.ps1
	. $PSScriptRoot\core\Get-M365SATChecks.ps1
	
	# Module Checkers
	. $PSScriptRoot\core\Check-M365SATModuleDuplicates.ps1
	. $PSScriptRoot\core\Check-M365SATModules.ps1
	. $PSScriptRoot\core\Update-M365SATModules.ps1
	. $PSScriptRoot\core\Check-M365SATUpdates.ps1
	
	# Import the PoShLog Module
	Import-Module PoShLog
	
	# Load Banner
	Banner
	
	# Create a New Logger
	Invoke-M365SATLogger -AllowLogging $AllowLogging -RootDirectory $RootDirectory
	
	Write-Host "$(Get-Date): Checking Existence SkipChecks Parameter..."
	if (!$SkipChecks.IsPresent)
	{
		# Checks if M365SAT has any updates
		Check-M365SATUpdates
		# Checks if all modules are installed and installs them if they are not
		Check-M365SATModules
		# Checks modules for updates
		Update-M365SATModules
		# Checks for duplicate modules and removes earlier versions
		Check-M365SATModuleDuplicates
	}
	Write-Host "$(Get-Date): Initiating Connections..."
	if (!$SkipLogin.IsPresent)
	{
		$OrgName = Connect-M365SAT -Username $Username -Password $Password -Modules $Modules -Environment $Environment
	}
	else
	{
		# Automatic Detection of the OrganizationName
		$OrgName = (((Get-MgOrganization).VerifiedDomains |  Where-Object { ($_.Name -like "*.onmicrosoft.com") -and ($_.Name -notlike "*mail.onmicrosoft.com") }).Name -split '.onmicrosoft.com')[0]
	}
	
	if ($LocalMode.IsPresent)
	{
		Write-Host "$(Get-Date): Getting Inspectors..."
		$inspectorlist = Get-M365SATLocalChecks -Directory $Directory -EnvironmentType $EnvironmentType -BenchmarkVersion $BenchmarkVersion -Modules $Modules -LicenseMode $LicenseMode -LicenseLevel $LicenseLevel #Gets list of all inspectors
		if ($ExpirimentalMode.IsPresent)
		{
			Write-Host "$(Get-Date): Executing Inspectors in MultiThread Mode..."
			$object = Invoke-M365SATChecksV2 -inspectors $inspectorlist -Directory $Directory
		}
		else
		{
			Write-Host "$(Get-Date): Executing Inspectors in SingleThread Mode..."
			$object = Invoke-M365SATCustomChecks -inspectors $inspectorlist -Directory $Directory
		}
	}
	else
	{
		Write-Host "$(Get-Date): Getting Inspectors..."
		$inspectorlist = Get-M365SATChecks -Directory $Directory -EnvironmentType $EnvironmentType -BenchmarkVersion $BenchmarkVersion -Modules $Modules -LicenseMode $LicenseMode -LicenseLevel $LicenseLevel #Gets list of all inspectors
		if ($ExpirimentalMode.IsPresent)
		{
			Write-Host "$(Get-Date): Creating Directories..."
			New-Item -ItemType Directory -Force -Path "$($OutPath)\evidence" | Out-Null
			Write-Host "$(Get-Date): Executing Inspectors in MultiThread Mode..."
			$object = Invoke-M365SATChecksV2 -inspectors $inspectorlist -Directory $Directory
		}
		else
		{
			Write-Host "$(Get-Date): Creating Directories..."
			New-Item -ItemType Directory -Force -Path "$($OutPath)\evidence" | Out-Null
			Write-Host "$(Get-Date): Executing Inspectors in SingleThread Mode..."
			$object = Invoke-M365SATChecks -inspectors $inspectorlist -Directory $Directory
		}
	}
	Write-Host "$(Get-Date): Generating Report..."
	
	# This to make sure you will get a report after all. JSON , CSV and the other output formats are coming in the next release!
	if ($reportType -eq "CSV")
	{
		. $PSScriptRoot\core\Get-M365SATCSVReport.ps1
		Get-M365SATCSVReport -object $object -OutPath $OutPath -Inspectors $inspectorlist
	}
	elseif ($reportType -eq "HTML")
	{
		. $PSScriptRoot\core\Get-M365SATHTMLReport.ps1
		Get-M365SATHTMLReport -object $object -OutPath $OutPath -Inspectors $inspectorlist
	}
	else
	{
		Write-Warning "Currently we only support .CSV and .HTML reporting. Defaulting to .HTML..."
		. $PSScriptRoot\core\Get-M365SATHTMLReport.ps1
		Get-M365SATHTMLReport -object $object -OutPath $OutPath -Inspectors $inspectorlist
	}
	
	
	Write-Host "$(Get-Date): Disconnecting Modules..."
	Disconnect-M365SAT -Modules $Modules # Disconnect All Modules after cleanup
	Write-Host "$(Get-Date): Cleaning Up..."
	Invoke-M365SATCleanup
	Close-Logger
}

