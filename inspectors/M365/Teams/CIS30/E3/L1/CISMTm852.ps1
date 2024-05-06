# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Teams
# Purpose: Ensure anonymous users and dial-in callers can't start a meeting
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm852($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMTm852"
		FindingName	     = "CISM Tm 8.5.2 - Anonymous users and dial-in callers can start a meeting"
		ProductFamily    = "Microsoft Teams"
		RiskScore	     = "15"
		Description	     = "Not allowing anonymous participants to automatically join a meeting reduces the risk of meeting spamming."
		Remediation	     = "Use the PowerShell script to disallow External Access"
		PowerShellScript = 'Set-CsTeamsMeetingPolicy -Identity Global -AllowAnonymousUsersToStartMeeting $false'
		DefaultValue	 = "True"
		ExpectedValue    = "False"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Manage anonymous participant access to Teams meetings, webinars, and town halls (IT admins)'; 'URL' = "https://learn.microsoft.com/en-us/microsoftteams/anonymous-users-in-meetings" })
	}
	return $inspectorobject
}

function Audit-CISMTm852
{
	try
	{
		$ViolatedTeamsSettings = @()
		$MicrosoftTeamsCheck = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowAnonymousUsersToStartMeeting
		
		
		if ($MicrosoftTeamsCheck.AllowAnonymousUsersToStartMeeting -eq $True)
		{
			$MicrosoftTeamsCheck | Format-Table -AutoSize | Out-File "$path\CISMTm852-TeamsMeetingPolicy.txt"
			$endobject = Build-CISMTm852($MicrosoftTeamsCheck.AllowAnonymousUsersToStartMeeting)
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
return Audit-CISMTm852