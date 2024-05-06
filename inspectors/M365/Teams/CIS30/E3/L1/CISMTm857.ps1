# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Teams
# Purpose: Ensure external participants can't give or request control
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm857($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMTm857"
		FindingName	     = "CISM Tm 8.5.7 - External participants can give or request control"
		ProductFamily    = "Microsoft Teams"
		RiskScore	     = "15"
		Description	     = "Ensuring that only authorized individuals and not external participants are able to present and request control reduces the risk that a malicious user can inadvertently show content that is not appropriate."
		Remediation	     = "Use the PowerShell script to disallow external participates to give or request control"
		PowerShellScript = 'Set-CsTeamsMeetingPolicy -Identity Global -AllowExternalParticipantGiveRequestControl $false'
		DefaultValue	 = "False"
		ExpectedValue    = "False"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Manage who can present and request control in Teams meetings'; 'URL' = "https://learn.microsoft.com/en-us/microsoftteams/meeting-who-present-request-control" })
	}
	return $inspectorobject
}

function Audit-CISMTm857
{
	try
	{
		$ViolatedTeamsSettings = @()
		$MicrosoftTeamsCheck = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object AllowExternalParticipantGiveRequestControl
		
		
		if ($MicrosoftTeamsCheck.AllowExternalParticipantGiveRequestControl -eq $True)
		{
			$MicrosoftTeamsCheck | Format-Table -AutoSize | Out-File "$path\CISMTm857-TeamsMeetingPolicy.txt"
			$endobject = Build-CISMTm857($MicrosoftTeamsCheck.AllowExternalParticipantGiveRequestControl)
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
return Audit-CISMTm857