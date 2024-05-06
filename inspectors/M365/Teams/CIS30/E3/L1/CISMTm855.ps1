# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Teams
# Purpose: Ensure meeting chat does not allow anonymous users
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm855($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMTm855"
		FindingName	     = "CISM Tm 8.5.5 - The meeting chat allows anonymous users"
		ProductFamily    = "Microsoft Teams"
		RiskScore	     = "15"
		Description	     = "Ensuring that only authorized individuals can read and write chat messages during a meeting reduces the risk that a malicious user can inadvertently show content that is not appropriate or view sensitive information."
		Remediation	     = "Use the PowerShell script to disallow External Access"
		PowerShellScript = 'Set-CsTeamsMeetingPolicy -Identity Global -MeetingChatEnabledType "EnabledExceptAnonymous"'
		DefaultValue	 = "Everyone"
		ExpectedValue    = "EnabledExceptAnonymous"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Set-CSTeamsMeetingPolicy'; 'URL' = "https://learn.microsoft.com/en-us/powershell/module/skype/set-csteamsmeetingpolicy?view=skype-ps#-meetingchatenabledtype" })
	}
	return $inspectorobject
}

function Audit-CISMTm855
{
	try
	{
		$ViolatedTeamsSettings = @()
		$MicrosoftTeamsCheck = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object MeetingChatEnabledType
		
		
		if ($MicrosoftTeamsCheck.MeetingChatEnabledType -ne "EnabledExceptAnonymous")
		{
			$MicrosoftTeamsCheck | Format-Table -AutoSize | Out-File "$path\CISMTm855-TeamsMeetingPolicy.txt"
			$endobject = Build-CISMTm855($MicrosoftTeamsCheck.MeetingChatEnabledType)
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
return Audit-CISMTm855