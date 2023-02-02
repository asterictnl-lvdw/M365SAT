# This is an DocumentSharingWLBL Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft SharePoint
# Purpose: Checks the Document Sharing Blacklist and Whitelist settings in SharePoint
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-DocumentSharingWLBL($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMSP0002"
		FindingName	     = "No Document Sharing Restriction Configured!"
		ProductFamily    = "Microsoft Sharepoint"
		CVS			     = "8.1"
		Description	     = "Attackers will often attempt to expose sensitive information to external entities through sharing, and restricting the domains that your users can share documents with will reduce that surface area."
		Remediation	     = "Run the PowerShell Command to put either a WhiteList or a BlackList to restrict sharing"
		DefaultValue	 = "None"
		ExpectedValue    = "Either an allowlist or blacklist containing domains"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		PowerShellScript = 'Set-SPOTenant -SharingDomainRestrictionMode AllowList -SharingAllowedDomainList "domain1.com domain2.com"'
		References	     = @(@{ 'Name' = '3.3 Configure Data Access Control Lists'; 'URL' = 'https://paper.bobylive.com/Security/CIS/CIS_Microsoft_365_Foundations_Benchmark_v1_4_0.pdf' },
			@{ 'Name' = '13.4 Only Allow Access to Authorized Cloud Storage or Email Providers'; 'URL' = 'https://paper.bobylive.com/Security/CIS/CIS_Microsoft_365_Foundations_Benchmark_v1_4_0.pdf' },
			@{ 'Name' = '14.6 Protect Information through Access Control Lists'; 'URL' = 'https://paper.bobylive.com/Security/CIS/CIS_Microsoft_365_Foundations_Benchmark_v1_4_0.pdf' })
	}
}

function Audit-DocumentSharingWLBL
{
	try
	{
		$DocumentSharingWLBLData = @()
		$DocumentSharingWLBL = Get-SPOTenant | select SharingDomainRestrictionMode, SharingAllowedDomainList
		if ($DocumentSharingWLBL.SharingDomainRestrictionMode -match 'None' -and $DocumentSharingWLBL.SharingAllowedDomainList -eq $null)
		{
			foreach ($DocumentSharingWLBLObj in $DocumentSharingWLBL)
			{
				$DocumentSharingWLBLData += " SharingDomainRestrictionMode: " + $DocumentSharingWLBL.SharingDomainRestrictionMode
				$DocumentSharingWLBLData += "`n SharingAllowedDomainList: " + $DocumentSharingWLBL.SharingAllowedDomainList
			}
			$endobject = Build-DocumentSharingWLBL($DocumentSharingWLBLData)
			return $endobject
		}
		return $null
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
return Audit-DocumentSharingWLBL