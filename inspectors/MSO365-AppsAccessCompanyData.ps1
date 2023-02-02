# This is an AppsAccessCompanyData Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Office 365
# Purpose: Checks if in Microsoft (Office) 365 Apps can access sensitive Company Data
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-AppsAccessCompanyData($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMO3650001"
		FindingName	     = "Apps can Access Sensitive Company Data."
		ProductFamily    = "Microsoft Office 365"
		CVS			     = "9.6"
		Description	     = "Attackers can commonly use custom applications to trick users into granting them access to company data."
		Remediation	     = "Run the PowerShell Command to mitigate this issue."
		PowerShellScript = 'Set-MsolCompanySettings -UsersPermissionToUserConsentToAppEnabled $False'
		DefaultValue	 = "True"
		ExpectedValue    = "False"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		References	     = @(@{ 'Name' = '3.3 Configure Data Access Control Lists'; 'URL' = "https://paper.bobylive.com/Security/CIS/CIS_Microsoft_365_Foundations_Benchmark_v1_4_0.pdf" },
			@{ 'Name' = '3.8 Document Data Flows'; 'URL' = "https://paper.bobylive.com/Security/CIS/CIS_Microsoft_365_Foundations_Benchmark_v1_4_0.pdf" },
			@{ 'Name' = '14.6 Protect Information through Access Control Lists'; 'URL' = "https://paper.bobylive.com/Security/CIS/CIS_Microsoft_365_Foundations_Benchmark_v1_4_0.pdf" })
	}
}

function Audit-AppsAccessCompanyData
{
	try
	{
		$appsaccesscompanydata = Get-MsolCompanyInformation | Select-Object UsersPermissionToUserConsentToAppEnabled
		if ($appsaccesscompanydata.UsersPermissionToUserConsentToAppEnabled -match 'True')
		{
			$endobject = Build-AppsAccessCompanyData('UsersPermissionToUserConsentToAppEnabled: ' + $appsaccesscompanydata.UsersPermissionToUserConsentToAppEnabled)
			Return $endobject
		}
		else
		{
			return $null
		}
	}
	catch
	{
		Write-Warning "Error message: $_"
		$message = $_.ToString()
		$exception = $_.Exception
		$strace = $_.ScriptStackTrace
		$failingline = $_.InvocationInfo.Line
		$positionmsg = $_.InvocationInfo.PositionMessage
		$pscommandpath = $_.InvocationInfo.PSCommandPath
		$failinglinenumber = $_.InvocationInfo.ScriptLineNumber
		$scriptname = $_.InvocationInfo.ScriptName
		Write-Verbose "Write to log"
		Write-ErrorLog -message $message -exception $exception -scriptname $scriptname
		Write-Verbose "Errors written to log"
	}
}
return Audit-AppsAccessCompanyData