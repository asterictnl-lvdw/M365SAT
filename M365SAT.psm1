#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
	.SYNOPSIS
		M365SAT - The Microsoft 365 Security Assessment Tool
    
    .VERSION
        Version 2.0 stable

    .RELEASE_DATE
        14-6-2023

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
        - Leonardo van de Weteringh © 2022
        
        ############################################################################

        URL: <githubURL>

        ############################################################################    

	.LINK
        github.com/asterlvdw/m365sat

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
		[Parameter(Mandatory = $true,
				   HelpMessage = 'Path to store the report, e.g. C:\out')]
		[string]$OutPath,
		[Parameter(Mandatory = $true,
				   HelpMessage = 'Enter the Global Administrator Username:')]
		[string]$Username,
		[Parameter(Mandatory = $false,
				   HelpMessage = 'Skips Module Updates (Experimental)')]
		[switch]$SkipChecks,
		[switch]$UseExpirimentalScanner,
		[Parameter(Mandatory = $true,
				   HelpMessage = 'Choose the Report Format. Default is CISV3. CISV2/CISV3')]
		[ValidateSet('CISV2', 'CISV3', IgnoreCase = $true)]
		[string]$AuditType = "CISV3",
		[switch]$SkipLogin,
		[Parameter(Mandatory = $false,
				   HelpMessage = 'Uses Custom Modules')]
		[switch]$UseCustomModules,
		[Parameter(Mandatory = $true,
				   HelpMessage = 'Choose the Report Format. Default is HTML. HTML / CSV / XML / CSMS')]
		[ValidateSet('HTML', 'CSV', 'XML', 'CSMS', IgnoreCase = $true)]
		[string]$reportType = "HTML",
		[Parameter(Mandatory = $false,
				   HelpMessage = 'New Debug Logger Verbose / Debug / Info / Warning / Error / Fatal')]
		[ValidateSet('Verbose', 'Debug', 'Info', 'Warning', 'Error', 'Fatal', IgnoreCase = $true)]
		[string]$AllowLogging = "Warning",
		[Parameter(Mandatory = $false,
				   HelpMessage = 'Available Modules: MicrosoftAzure / MicrosoftExchange / MicrosoftOffice365 / MicrosoftSharepoint / MicrosoftTeams / All')]
		[ValidateSet('MicrosoftAzure', 'MicrosoftExchange', 'MicrosoftOffice 365', 'MicrosoftSharepoint', 'MicrosoftTeams', 'All', IgnoreCase = $true)]
		[string]$Modules = "All",
		[string]$Password
	)
	
	# Variables
	$tempfiles = @()
	$MaximumFunctionCount = 32768
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
	
	# Import the PoShLog Module
	Import-Module PoShLog
	
	# Load Banner
	Banner
	
	# Create a New Logger
	Invoke-M365SATLogger($AllowLogging)
	
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
		$OrgName = Connect-M365SAT($Username, $Password)
	}
	else
	{
		# Automatic Detection of the OrganizationName
		$OrgName = (((Get-MgOrganization).VerifiedDomains |  Where-Object { ($_.Name -like "*.onmicrosoft.com") -and ($_.Name -notlike "*mail.onmicrosoft.com") }).Name -split '.onmicrosoft.com')[0]
	}
	
	if ($UseCustomModules.IsPresent)
	{
		Write-Host "$(Get-Date): Getting Inspectors..."
		$inspectorlist = Get-M365SATLocalChecks -Directory $Directory -Modules $Modules -CustomModules $UseCustomModules -AuditType $AuditType #Gets list of all inspectors
		if ($UseExpirimentalScanner.IsPresent)
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
		$inspectorlist = Get-M365SATChecks -Directory $Directory -Modules $Modules -CustomModules -AuditType $AuditType #Gets list of all inspectors
		if ($UseExpirimentalScanner.IsPresent)
		{
			Write-Host "$(Get-Date): Executing Inspectors in MultiThread Mode..."
			$object = Invoke-M365SATChecksV2 -inspectors $inspectorlist -Directory $Directory
		}
		else
		{
			Write-Host "$(Get-Date): Executing Inspectors in SingleThread Mode..."
			$object = Invoke-M365SATChecks -inspectors $inspectorlist -Directory $Directory
		}
	}
	Write-Host "$(Get-Date): Generating Report..."
	
	# This to make sure you will get a report after all. JSON , CSV and the other output formats are coming in the next release!
	if ($reportType -ne "HTML")
	{
		Write-WarningLog "Currently there is no other output supported. "
		$reportType = "HTML"
	}
	if ($reportType -eq "HTML")
	{
		. $PSScriptRoot\core\Get-M365SATHTMLReport.ps1
		Get-M365SATHTMLReport -object $object -OutPath $OutPath -Inspectors $inspectorlist
	}
	
	
	Write-Host "$(Get-Date): Disconnecting Modules..."
	Disconnect-M365SAT # Disconnect All Modules after cleanup
	Write-Host "$(Get-Date): Cleaning Up..."
	Invoke-M365SATCleanup
	Close-Logger
}

