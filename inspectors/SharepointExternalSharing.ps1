# This is an SharepointExternalSharing Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft SharePoint
# Purpose: Checks which External Sharing is permitted to do
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-SharepointExternalSharing($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMSP0004"
		FindingName	     = "SharePoint External Sharing Enabled (Global)"
		ProductFamily    = "Microsoft SharePoint"
		CVS			     = "8.2"
		Description	     = "SharePoint is the organization's hub for sharing files amongst each other. SharePoint can also permit users to share content with anonymous outsiders or members of other organizations (commonly referred to as 'external users'). Sharing with external users and guests is currently enabled in this instance of SharePoint. This setting may increase the probability of sensitive information being shared outside of the organization, either accidentally or as a means of data exfiltration by a cyber adversary with access to the organizational environment. Consider disabling this setting for the sake of preventing such occurrences if there is no intention of sharing information outside of the organization as part of the organization's mission. However, note that some degree of external sharing is vital for many organizations. Furthermore, disabling external sharing is not necessarily a panacea for problems related to confidential information, as users may still mistakenly or maliciously share confidential information through a number of channels. Continue to apply good sense in data loss prevention and other forms of monitoring even if external sharing is disabled."
		Remediation	     = "Limit Sharing to External Users by executing the PowerShell command."
		DefaultValue	 = "ExternalUserAndGuestSharing (Anyone)"
		ExpectedValue    = "ExternalUserSharingOnly (New and Existing Guests)"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		PowerShellScript = 'Set-SPOTenant -SharingCapability Disabled / Set-PnPTenant -SharingCapability Disabled'
		References	     = @(@{ 'Name' = 'Manage sharing settings'; 'URL' = 'https://docs.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-off' },
			@{ 'Name' = 'Limit sharing in M365'; 'URL' = 'https://docs.microsoft.com/en-us/microsoft-365/solutions/microsoft-365-limit-sharing?view=o365-worldwide' })
	}
}


function Inspect-SharepointExternalSharing
{
	Try
	{
		
		$sharing_capability = (Get-SPOTenant).SharingCapability
		If ($sharing_capability -ne "Disabled")
		{
			If ($sharing_capability -eq "ExternalUserAndGuestSharing")
			{
				$sharing_capability = "ExternalUserAndGuestSharing (Anyone)"
			}
			elseif ($sharing_capability -eq "ExternalUserSharingOnly")
			{
				$sharing_capability = "ExternalUserSharingOnly (New and Existing Guests)"
			}
			elseif ($sharing_capability -eq "ExistingExternalUserSharingOnly")
			{
				$sharing_capability = "ExistingExternalUserSharingOnly (Existing Guests)"
			}
			$message = $org_name + ": " + "Sharing capability is " + $sharing_capability + "."
			$endobject = Build-SharepointExternalSharing($message)
			return $endobject
		}
		
		return $null
		
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

return Inspect-SharepointExternalSharing


