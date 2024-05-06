# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure Microsoft Defender for Cloud Apps is enabled and configured
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz243($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz243"
		FindingName	     = "CIS MAz 2.4.3 - Unable to verify if Microsoft Defender for Cloud Apps is enabled and configured"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "Security teams can receive notifications of triggered alerts for atypical or suspicious activities, see how the organization's data in Microsoft 365 is accessed and used, suspend user accounts exhibiting suspicious activity, and require users to log back in to Microsoft 365 apps after an alert has been triggered"
		Remediation	     = "The implementation of Microsoft Defender for Cloud App MUST be done manually, because there is no automatic script available at this moment."
		PowerShellScript = 'https://learn.microsoft.com/en-us/defender-cloud-apps/get-started'
		DefaultValue	 = "No Microsoft Defender for Cloud Apps active"
		ExpectedValue    = "Microsoft Defender for Cloud Apps active"
		ReturnedValue    = "$findings"
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Microsoft Defender for Cloud Apps - Get Started'; 'URL' = 'https://learn.microsoft.com/en-us/defender-cloud-apps/get-started' },
			@{ 'Name' = 'Microsoft Defender for Cloud Apps - Policies'; 'URL' = 'https://learn.microsoft.com/en-us/defender-cloud-apps/protect-office-365' })
	}
	return $inspectorobject
}

function Audit-CISMAz243
{
	try
	{

		$finalobject = Build-CISMAz243($Groups)
		return $finalobject
		return $null
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISMAz243