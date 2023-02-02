#Requires -Version 5.1

<#
	.SYNOPSIS
		M365SAT - The Microsoft 365 Security Assessment Tool
    
    .VERSION
        Version 1.0 stable

    .RELEASE_DATE
        11-11-2022

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

$tempfiles = @()

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
		mkdir $Directory | out-null
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
	param (
		[Parameter(Mandatory = $true,
				   HelpMessage = 'Organization Name, e.g. contoso')]
		[string]$OrgName,
		[Parameter(Mandatory = $true,
				   HelpMessage = 'Path to store the report, e.g. C:\out')]
		[string]$OutPath,
		[Parameter(Mandatory = $false,
				   HelpMessage = 'Enter Global Administrator Username')]
		[string]$Username,
		[Parameter(Mandatory = $false,
				   HelpMessage = 'Enter Global Administrator Password')]
		[string]$Password,
		[Parameter(Mandatory = $true,
				   HelpMessage = "ReportTypeFormat: HTML / CSV / XML")]
		[ValidateSet("HTML", "CSV", "XML",
					 IgnoreCase = $true)]
		[string]$reportType = "HTML",
		[Parameter(Mandatory = $false,
				   HelpMessage = 'Skip Update Check')]
		[switch]$SkipChecks,
		[Parameter(Mandatory = $false,
				   HelpMessage = 'Use Local Modules Instead of Downloading Online')]
		[switch]$UseCustomModules,
		[Parameter(Mandatory = $false,
				   HelpMessage = 'Selected Inspectors')]
		[string[]]$SelectedInspectors = @(),
		[Parameter(Mandatory = $false,
				   HelpMessage = 'Excluded Inspectors')]
		[string[]]$ExcludedInspectors = @()
	)
	
	$Directory = "$PSScriptRoot\inspectors"
	
	. $PSScriptRoot\modules\welcome\welcome.ps1 # Displays Banner
	Banner
	. $PSScriptRoot\core\checkadminprivileges\checkadmin.ps1 # Checks if Script is Ran as Admin...
	CheckAdminPrivBeta
	
	# Load all Modules in .\core directory
	Write-Host "$(Get-Date): Loading all Modules"
	ForEach ($Item in Get-ChildItem -Path .\core -Recurse -Filter '*.ps1')
	{
		Write-Host ("{0}: Loading {1} module:" -f (Get-Date), $Item.FullName)
		. $Item.FullName # Loads Module
	}
	Write-Host "$(Get-Date): Checking Existence SkipChecks Parameter..."
	if (!$SkipChecks.IsPresent)
	{
		# Checks if M365SAT has any updates
		. $PSScriptRoot\modules\m365satupdater\m365updater.ps1
		Start-M365SATPlusCheck
		# Checks if all modules are installed and installs them if they are not
		. $PSScriptRoot\modules\modulechecker\modulechecker.ps1
		Initialize-M365SATModuleCheckModules
		# Checks modules for updates
		. $PSScriptRoot\modules\moduleupdater\moduleupdater.ps1
		Invoke-M365SATModuleUpdates
		# Checks for duplicate modules and removes earlier versions
		. $PSScriptRoot\modules\moduleduplicatechecker\moduleduplicatechecker.ps1
		Get-DuplicateModules
	}
	Write-Host "$(Get-Date): Initiating Connections..."
	try
	{
		. $PSScriptRoot\core\m365connector\moduleconnector.ps1
		Invoke-M365SATConnections($OrgName) #Invoking Connections
	}
	catch
	{
		Write-Error "An Error has Occured!"
	}
	if ($UseCustomModules.IsPresent)
	{
		. $PSScriptRoot\core\getinspectors\getinspectors.ps1
		. $PSScriptRoot\core\executeinspectors\executeinspectors.ps1
		Write-Host "$(Get-Date): Getting Inspectors..."
		$inspectorlist = Get-M365SATInspectorsOffline($Directory) #Gets list of all inspectors
		Write-Host "$(Get-Date): Executing Inspectors..."
		$object = Run-M365SATLocalInspectors -inspectors $inspectorlist -Directory $Directory
	}
	else
	{
		Write-Host "$(Get-Date): Getting Inspectors..."
		$inspectorlist = Get-M365SATGetInspectors #Gets list of all inspectors
		Write-Host "$(Get-Date): Executing Inspectors..."
		$object = Run-M365SATInspectors($inspectorlist)
	}
	Write-Host "$(Get-Date): Generating Report..."
	if ($reportType -eq "HTML")
	{
		. $PSScriptRoot\Output\output-html.ps1
		Get-M365SATReportHTML -object $object -OutPath $OutPath -Inspectors $inspectorlist
	}
	elseif ($reportType -eq "CSV")
	{
		. $PSScriptRoot\Output\output-csv.ps1
		Get-M365SATReportCSV -object $object -OutPath $OutPath -Inspectors $inspectorlist
	}
	elseif ($reportType -eq "cosmos")
	{
		. $PSScriptRoot\Output\output-cosmos.ps1
		Get-M365SATReportCosmos -object $object -OutPath $OutPath -Inspectors $inspectorlist
	}
	else
	{
		. $PSScriptRoot\Output\output-json.ps1
		Get-M365SATReportJSON -object $object -OutPath $OutPath -Inspectors $inspectorlist
	}
	Write-Host "$(Get-Date): Disconnecting Modules..."
	. $PSScriptRoot\core\m365disconnector\moduledisconnector.ps1
	Invoke-M365SATModuleDisconnection # Disconnect All Modules after cleanup
	Write-Host "$(Get-Date): Cleaning Up..."
	Invoke-M365SATCleanup
}
