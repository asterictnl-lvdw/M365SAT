# This is an ExternalUserResharing Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft SharePoint
# Purpose: Checks which External Users can Reshare the same document
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-SharepointExternalUserResharing($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMSP0005"
		FindingName	     = "SharePoint External User Resharing Permitted"
		ProductFamily    = "Microsoft SharePoint"
		CVS			     = "9.3"
		Description	     = "SharePoint is the organization's hub for sharing files amongst each other. SharePoint can also permit users to share content with anonymous outsiders or members of other organizations (commonly referred to as 'external users'). Current SharePoint settings are configured such that, if users share a file with an external user, that external user can re-share the file arbitrarily with other external users. This is a highly permissive setting that could result in the unsafe propagation of the organization's confidential information in ways that may not be fully intended."
		Remediation	     = "Use the PowerShell script to mitigate this issue."
		DefaultValue	 = "False"
		ExpectedValue    = "True"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		PowerShellScript = 'Set-SPOTenant -PreventExternalUsersFromResharing $true'
		References	     = @(@{ 'Name' = 'Manage sharing settings'; 'URL' = 'https://docs.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-off' },
			@{ 'Name' = 'Limit sharing in M365'; 'URL' = 'https://docs.microsoft.com/en-us/microsoft-365/solutions/microsoft-365-limit-sharing?view=o365-worldwide' })
	}
}

function Inspect-SharepointExternalUserResharing
{
	Try
	{
		
		If ((Get-SPOTenant).SharingCapability -ne "Disabled")
		{
			If (-NOT (Get-SPOTenant).PreventExternalUsersFromResharing)
			{
				$endobject = Build-SharepointExternalUserResharing("Tenant PreventExternalUsersFromResharing configuration: $((Get-SPOTenant).PreventExternalUsersFromResharing)")
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

return Inspect-SharepointExternalUserResharing


