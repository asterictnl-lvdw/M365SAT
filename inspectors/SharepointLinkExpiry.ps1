# This is an SharepointLinkExpiry Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft SharePoint
# Purpose: Checks if SharePoint Anonymous Links and any other links expire after a period of time
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-SharepointLinkExpiry($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMSP0007"
		FindingName	     = "SharePoint 'Anyone' Shared Links Never Expire"
		ProductFamily    = "Microsoft SharePoint"
		CVS			     = "9.3"
		Description	     = "The organization's instance of SharePoint is set to never expire links to documents accessible by the 'Anyone' group. 'Anyone' links that exist indefinitely could be abused by an adversary or enable leakage of sensitive information in multiple ways. A value of -1 indicates anonymous links never expire. It is suggested that these links expire eventually to control possible information disclosure."
		Remediation	     = "Use the PowerShell Script to remediate the issue"
		DefaultValue	 = "-1"
		ExpectedValue    = "Value of 1 or higher"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		PowerShellScript = 'Set-SPOTenant -RequireAnonymousLinksExpireInDays 15;'
		References	     = @(@{ 'Name' = 'Set Anonymous Link Expiration Settings for SharePoint Online and OneDrive for Business'; 'URL' = 'https://www.sharepointdiary.com/2017/09/set-anonymous-link-expiration-in-sharepoint-online.html' })
	}
}


function Inspect-SharepointLinkExpiry
{
	Try
	{
		
		If ((Get-SPOTenant).SharingCapability -eq "ExternalUserAndGuestSharing")
		{
			If ((Get-SPOTenant).RequireAnonymousLinksExpireInDays -eq -1)
			{
				$Days = (Get-SPOTenant).RequireAnonymousLinksExpireInDays
				$endobject = Build-SharepointLinkExpiry($Days)
				return $endobject
			}
			Else
			{
				return $null
			}
		}
		
	}
	Catch
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

return Inspect-SharepointLinkExpiry


