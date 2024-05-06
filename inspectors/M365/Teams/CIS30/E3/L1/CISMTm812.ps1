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

function Build-CISMTm812($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMTm812"
		FindingName	     = "CISM Tm 8.1.2 - Users can send emails to a channel emailaddress"
		ProductFamily    = "Microsoft Teams"
		RiskScore	     = "15"
		Description	     = "Channel email addresses are not under the tenant's domain and organizations do not have control over the security settings for this email address. An attacker could email channels directly if they discover the channel email address."
		Remediation	     = "Use the PowerShell script to disallow Emails into Channels:"
		PowerShellScript = 'Set-CsTeamsClientConfiguration -Identity Global -AllowEmailIntoChannel $false'
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

function Audit-CISMTm812
{
	try
	{
		$ViolatedTeamsSettings = @()
		$MicrosoftTeamsCheck = Get-CsTeamsClientConfiguration -Identity Global | Select-Object AllowEmailIntoChannel
		
		
		if ($MicrosoftTeamsCheck.AllowEmailIntoChannel -eq $True)
		{
			$MicrosoftTeamsCheck | Format-Table -AutoSize | Out-File "$path\CISMTm812-TeamsClientConfiguration.txt"
			$endobject = Build-CISMTm812($MicrosoftTeamsCheck.AllowEmailIntoChannel)
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
return Audit-CISMTm812