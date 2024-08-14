# Date: 14-05-2024
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.1.0
# Product Family: Microsoft Teams
# Purpose: Ensure external meeting chat is off (Automated)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm858($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMTm858"
		FindingName	     = "CISM Tm 8.5.8 - External meeting chat is on"
		ProductFamily    = "Microsoft Teams"
		RiskScore	     = "15"
		Description	     = "This meeting policy setting controls whether users can read or write messages in external meeting chats with untrusted organizations. If an external organization is on the list of trusted organizations this setting will be ignored. Restricting access to chat in meetings hosted by external organizations limits the opportunity for an exploit like GIFShell or DarkGate malware from being delivered to users"
		Remediation	     = "Use the PowerShell script to disallow External Access"
		PowerShellScript = 'Set-CsTeamsMeetingPolicy -Identity Global -AllowExternalNonTrustedMeetingChat $false'
		DefaultValue	 = "True"
		ExpectedValue    = "False"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Teams settings and policies reference'; 'URL' = "https://learn.microsoft.com/en-US/microsoftteams/settings-policies-reference?WT.mc_id=TeamsAdminCenterCSH#meeting-engagement" })
	}
	return $inspectorobject
}

function Audit-CISMTm858
{
	try
	{
		$ViolatedTeamsSettings = @()
		$MicrosoftTeamsCheck = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowExternalNonTrustedMeetingChat
		
		
		if ($MicrosoftTeamsCheck.AllowExternalNonTrustedMeetingChat -eq $True)
		{
			$MicrosoftTeamsCheck | Format-Table -AutoSize | Out-File "$path\CISMTm858-TeamsMeetingPolicy.txt"
			$endobject = Build-CISMTm858($MicrosoftTeamsCheck.AllowExternalNonTrustedMeetingChat)
			return $endobject
		}
		return $null
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISMTm858