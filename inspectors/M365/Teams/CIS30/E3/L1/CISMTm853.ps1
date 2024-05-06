# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Teams
# Purpose: Ensure external file sharing in Teams is enabled for only approved cloud storage services
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm853($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMTm853"
		FindingName	     = "CISM Tm 8.5.3 - Everyone can bypass the lobby"
		ProductFamily    = "Microsoft Teams"
		RiskScore	     = "15"
		Description	     = "For meetings that could contain sensitive information, it is best to allow the meeting organizer to vet anyone not directly sent an invite before admitting them to the meeting. This will also prevent the anonymous user from using the meeting link to have meetings at unscheduled times."
		Remediation	     = "Use the PowerShell script to disallow External Access"
		PowerShellScript = 'Set-CsTeamsMeetingPolicy -Identity Global -AutoAdmittedUsers "EveryoneInCompanyExcludingGuests"'
		DefaultValue	 = "True"
		ExpectedValue    = "False"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Restricting channel email messages to approved domains'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/step-by-step-guides/reducing-attack-surface-in-microsoft-teams?view=o365-worldwide#restricting-channel-email-messages-to-approved-domains" })
	}
	return $inspectorobject
}

function Audit-CISMTm853
{
	try
	{
		$ViolatedTeamsSettings = @()
		$MicrosoftTeamsCheck = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowEmailIntoChannel
		
		
		if ($MicrosoftTeamsCheck.AllowEmailIntoChannel -ne "EveryoneInCompanyExcludingGuests")
		{
			$MicrosoftTeamsCheck | Format-Table -AutoSize | Out-File "$path\CISMTm853-TeamsMeetingPolicy.txt"
			$endobject = Build-CISMTm853($MicrosoftTeamsCheck.AllowEmailIntoChannel)
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
return Audit-CISMTm853