# This is an ExternalCalendarSharing Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if Calendars are Externally Shared with other people outside your organization
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Define Path
$path = @($OutPath)

function Build-ExternalCalendarSharing($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0023"
		FindingName	     = "Multiple Policies Not Enabled found by ConfigAnalyzerPolicyRecommendations!"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "5.3"
		Description	     = "Due to the enabled sharing policies listed above, the organization's users are permitted to share their Office 365 Calendars with any external person. It is not recommended to allow calendar sharing to users outside the organization as the data in calendar entries may reveal sensitive information about the organization or users."
		Remediation	     = "Use the PowerShell script or references to remediate this issue."
		PowerShellScript = 'Enable-OrganizationCustomization; Set-SharingPolicy -Identity "Default Sharing Policy" -Domains @{Remove="Anonymous:CalendarSharingFreeBusyReviewer", "Anonymous:CalendarSharingFreeBusySimple", "Anonymous:CalendarSharingFreeBusyDetail"}; Set-SharingPolicy -Identity "Default Sharing Policy" -Domains "*:CalendarSharingFreeBusySimple"'
		DefaultValue	 = "0"
		ExpectedValue    = "0"
		ReturnedValue    = $findings.ToString()
		Impact		     = "Medium"
		RiskRating	     = "Medium"
		References	     = @(@{ 'Name' = 'Modify a sharing policy'; 'URL' = "https://docs.microsoft.com/en-us/exchange/sharing/sharing-policies/modify-a-sharing-policy" },
			@{ 'Name' = 'Create a sharing policy in Exchange Online'; 'URL' = "https://docs.microsoft.com/en-us/exchange/sharing/sharing-policies/create-a-sharing-policy" },
			@{ 'Name' = 'ThatLazyAdmin: Disabling anonymous calendar sharing'; 'URL' = "https://www.thatlazyadmin.com/disable-anonymous-calendar-sharing-office-365-admin-center-powershell/" })
	}
	return $inspectorobject
}


function Inspect-ExternalCalendarSharing
{
	Try
	{
		
		$enabled_share_policies = Get-SharingPolicy | Where-Object -FilterScript { $_.Enabled }
		$enabled_external_share_policies = @()
		
		ForEach ($policy in $enabled_share_policies)
		{
			$domains = $policy | Select-Object -ExpandProperty Domains
			$calendar_sharing_anon = ($domains -like 'Anonymous:Calendar*')
			If ($calendar_sharing_anon.Count -NE 0)
			{
				$enabled_external_share_policies += $policy.Name
			}
		}
		
		If ($enabled_external_share_policies.Count -NE 0)
		{
			$endobject = Build-ExternalCalendarSharing($calendar_sharing_anon.Count)
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

return Inspect-ExternalCalendarSharing


