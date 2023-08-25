# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Sharepoint
# Purpose: Ensure Idle Browser SignOut is correctly configured
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Sp004($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Sp004"
		FindingName	     = "CSTM-Sp004 - Outgoing Sharing Invitations are Not Monitored"
		ProductFamily    = "Microsoft SharePoint"
		RiskScore	     = "12"
		Description	     = "SharePoint is the de-facto sharing and file management tool in the O365 suite. SharePoint provides administrators with the ability to record and monitor when their users have sent file sharing invitations to external users. This feature should be enabled, but it was detected as disabled. This feature could be vital in a detection or response capacity in cases where data was lost or shared inappropriately."
		Remediation	     = "Use the PowerShell Script to mitigate this issue:"
		DefaultValue	 = "None"
		ExpectedValue    = "A configured mailbox recipient"
		ReturnedValue    = $findings
		Impact		     = "4"
		Likelihood	     = "3"
		RiskRating	     = "High"
		Priority		 = "High"
		PowerShellScript = 'Set-SPOTenant -BccExternalSharingInvitations $true -BccExternalSharingInvitationsList "administrator@yourdomain"'
		References	     = @(@{ 'Name' = 'Reference - Set-SPOTenant'; 'URL' = 'https://docs.microsoft.com/en-us/powershell/module/sharepoint-online/set-spotenant?view=sharepoint-ps' },
			@{ 'Name' = 'SharePoint Diary: SharePoint Online External Sharing invitations.'; 'URL' = 'https://www.sharepointdiary.com/2020/01/shareoint-online-external-sharing-alerts.html' })
	}
}



function Inspect-CSTM-Sp004
{
	Try
	{
		
		$tenant = Get-SPOTenant
		
		If ($tenant.SharingCapability -ne "Disabled")
		{
			If ((-NOT $tenant.BccExternalSharingInvitations) -OR (-NOT $tenant.BccExternalSharingInvitationsList))
			{
				$endobject = Build-CSTM-Sp004("No configured recipients.")
				return $endobject
			}
			Else
			{
				return $null
			}
		}
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Inspect-CSTM-Sp004


