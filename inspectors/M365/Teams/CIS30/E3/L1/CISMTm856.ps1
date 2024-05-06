# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Teams
# Purpose: Ensure only organizers and co-organizers can present
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm856($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMTm856"
		FindingName	     = "CISM Tm 8.5.6 - Not only organizers and co-organizers can present, but also other users"
		ProductFamily    = "Microsoft Teams"
		RiskScore	     = "15"
		Description	     = "Ensuring that only authorized individuals are able to present reduces the risk that a malicious user can inadvertently show content that is not appropriate."
		Remediation	     = "Use the PowerShell script to allow only organizers and co-organizers to present:"
		PowerShellScript = 'Set-CsTeamsMeetingPolicy -Identity Global -DesignatedPresenterRoleMode "OrganizerOnlyUserOverride"'
		DefaultValue	 = "Everyone"
		ExpectedValue    = "OrganizerOnlyUserOverride"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Manage who can present and request control in Teams meetings'; 'URL' = "https://learn.microsoft.com/en-US/microsoftteams/meeting-who-present-request-control" })
	}
	return $inspectorobject
}

function Audit-CISMTm856
{
	try
	{
		$ViolatedTeamsSettings = @()
		$MicrosoftTeamsCheck = Get-CsTeamsMeetingPolicy -Identity Global | Select-Object DesignatedPresenterRoleMode
		
		
		if ($MicrosoftTeamsCheck.DesignatedPresenterRoleMode -ne "OrganizerOnlyUserOverride")
		{
			$MicrosoftTeamsCheck | Format-Table -AutoSize | Out-File "$path\CISMTm856-TeamsMeetingPolicy.txt"
			$endobject = Build-CISMTm856($MicrosoftTeamsCheck.DesignatedPresenterRoleMode)
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
return Audit-CISMTm856