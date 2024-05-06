# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Teams
# Purpose: Ensure users dialing in can't bypass the lobby
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm854($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMTm854"
		FindingName	     = "CISM Tm 8.5.4 - Users dialing in can bypass the lobby"
		ProductFamily    = "Microsoft Teams"
		RiskScore	     = "15"
		Description	     = "For meetings that could contain sensitive information, it is best to allow the meeting organizer to vet anyone not directly from the organization."
		Remediation	     = "Use the PowerShell script to disallow Bypassing the lobby"
		PowerShellScript = 'Set-CsTeamsMeetingPolicy -Identity Global -AllowPSTNUsersToBypassLobby $false'
		DefaultValue	 = "False"
		ExpectedValue    = "False"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Choose who can bypass the lobby in meetings hosted by your organization'; 'URL' = "https://learn.microsoft.com/en-US/microsoftteams/who-can-bypass-meeting-lobby?WT.mc_id=TeamsAdminCenterCSH#choose-who-can-bypass-the-lobby-in-meetings-hosted-by-your-organization" })
	}
	return $inspectorobject
}

function Audit-CISMTm854
{
	try
	{
		$ViolatedTeamsSettings = @()
		$MicrosoftTeamsCheck = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowPSTNUsersToBypassLobby
		
		
		if ($MicrosoftTeamsCheck.AllowPSTNUsersToBypassLobby -eq $True)
		{
			$MicrosoftTeamsCheck | Format-Table -AutoSize | Out-File "$path\CISMTm854-TeamsMeetingPolicy.txt"
			$endobject = Build-CISMTm854($MicrosoftTeamsCheck.AllowPSTNUsersToBypassLobby)
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
return Audit-CISMTm854