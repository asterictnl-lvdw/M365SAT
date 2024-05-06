# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure that Microsoft Defender for Endpoint integration with Microsoft Defender for Cloud is selected
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz2121($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz2121"
		FindingName	     = "CIS Az 2.1.21 - Microsoft Defender for Endpoint integration with Microsoft Defender for Cloud is not Selected"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Microsoft Defender for Endpoint integration brings comprehensive Endpoint Detection and Response (EDR) capabilities within Microsoft Defender for Cloud. This integration helps to spot abnormalities, as well as detect and respond to advanced attacks on endpoints monitored by Microsoft Defender for Cloud. MDE works only with Standard Tier subscriptions."
		Remediation	     = "You can change the settings in the URL written in PowerShellScript."
		PowerShellScript = 'https://portal.azure.com/#view/Microsoft_Azure_SubscriptionManagement/ManageSubscriptionPoliciesBlade'
		DefaultValue	 = "Null"
		ExpectedValue    = "True"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Understand endpoint detection and response'; 'URL' = 'https://learn.microsoft.com/en-in/azure/defender-for-cloud/integration-defender-for-endpoint?tabs=windows' })
	}
	return $inspectorobject
}

function Audit-CISAz2121
{
	try
	{
		$Settings = Get-AzSecuritySetting | Select-Object name, enabled | where-object { $_.name -eq "WDATP" }
		
		if ($Settings.enabled -eq $False)
		{
			$finalobject = Build-CISAz2121($Settings.enabled)
			return $finalobject
		}
		return $null
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISAz2121