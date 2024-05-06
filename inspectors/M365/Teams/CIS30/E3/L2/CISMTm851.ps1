# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Teams
# Purpose: Ensure anonymous users can't join a meeting
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm851($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMTm851"
		FindingName	     = "CISM Tm 8.5.1 - Anonymous users can join a meeting"
		ProductFamily    = "Microsoft Teams"
		RiskScore	     = "15"
		Description	     = "For meetings that could contain sensitive information, it is best to allow the meeting organizer to vet anyone not directly sent an invite before admitting them to the meeting. This will also prevent the anonymous user from using the meeting link to have meetings at unscheduled times"
		Remediation	     = "Use the PowerShell script to disallow External Access"
		PowerShellScript = 'Set-CsTeamsMeetingPolicy -Identity Global -AllowAnonymousUsersToJoinMeeting $false'
		DefaultValue	 = "True"
		ExpectedValue    = "False"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Configure Teams meetings with protection for sensitive data'; 'URL' = "https://learn.microsoft.com/en-us/MicrosoftTeams/configure-meetings-sensitive-protection" })
	}
	return $inspectorobject
}

function Audit-CISMTm851
{
	try
	{
		$ViolatedTeamsSettings = @()
		$MicrosoftTeamsCheck = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowAnonymousUsersToJoinMeeting
		
		
		if ($MicrosoftTeamsCheck.AllowAnonymousUsersToJoinMeeting -eq $True)
		{
			$MicrosoftTeamsCheck | Format-Table -AutoSize | Out-File "$path\CISMTm851-TeamsMeetingPolicy.txt"
			$endobject = Build-CISMTm851($MicrosoftTeamsCheck.AllowAnonymousUsersToJoinMeeting)
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
return Audit-CISMTm851