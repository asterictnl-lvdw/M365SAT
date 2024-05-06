# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that Auto provisioning of 'Vulnerability assessment for machines' is Set to 'On'
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz2117($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz2117"
		FindingName	     = "CIS Az 2.1.17 - Check if Auto provisioning of Microsoft Defender for Containers components is Set to On"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "5"
		Description	     = "As with any compute resource, Container environments require hardening and run-time protection to ensure safe operations and detection of threats and vulnerabilities."
		Remediation	     = "Check if the setting is activated. If not please do activate it. You can ignore this informational finding in the future if enabled."
		PowerShellScript = 'https://portal.azure.com/#view/Microsoft_Azure_SubscriptionManagement/ManageSubscriptionPoliciesBlade'
		DefaultValue	 = "Disabled"
		ExpectedValue    = "Enabled"
		ReturnedValue    = "$findings"
		Impact		     = "1"
		Likelihood	     = "5"
		RiskRating	     = "Low"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Overview of Microsoft Defender for Containers?'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction' })
	}
	return $inspectorobject
}

function Audit-CISAz2117
{
	try
	{
			$finalobject = Build-CISAz2117("Unknown")
			return $finalobject
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISAz2117