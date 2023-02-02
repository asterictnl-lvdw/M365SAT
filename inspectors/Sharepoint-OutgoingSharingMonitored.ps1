# This is an OutgoingSharingMonitored Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft SharePoint
# Purpose: Checks if SharePoint Modern Authentication is enabled
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-OutgoingSharingMonitored($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMSP0009"
		FindingName	     = "Outgoing Sharing Invitations are Not Monitored"
		ProductFamily    = "Microsoft SharePoint"
		CVS			     = "7.5"
		Description	     = "SharePoint is the de-facto sharing and file management tool in the O365 suite. SharePoint provides administrators with the ability to record and monitor when their users have sent file sharing invitations to external users. This feature should be enabled, but it was detected as disabled. This feature could be vital in a detection or response capacity in cases where data was lost or shared inappropriately."
		Remediation	     = "Use the PowerShell Script to mitigate this issue:"
		DefaultValue	 = "None"
		ExpectedValue    = "A configured mailbox recipient"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		PowerShellScript = 'Set-SPOTenant -BccExternalSharingInvitations $true -BccExternalSharingInvitationsList "administrator@yourdomain"'
		References	     = @(@{ 'Name' = 'Reference - Set-SPOTenant'; 'URL' = 'https://docs.microsoft.com/en-us/powershell/module/sharepoint-online/set-spotenant?view=sharepoint-ps' },
			@{ 'Name' = 'SharePoint Diary: SharePoint Online External Sharing invitations.'; 'URL' = 'https://www.sharepointdiary.com/2020/01/shareoint-online-external-sharing-alerts.html' })
	}
}



function Inspect-OutgoingSharingMonitored
{
	Try
	{
		
		$tenant = Get-SPOTenant
		
		If ($tenant.SharingCapability -ne "Disabled")
		{
			If ((-NOT $tenant.BccExternalSharingInvitations) -OR (-NOT $tenant.BccExternalSharingInvitationsList))
			{
				$endobject = Build-OutgoingSharingMonitored("No configured recipients.")
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

return Inspect-OutgoingSharingMonitored


