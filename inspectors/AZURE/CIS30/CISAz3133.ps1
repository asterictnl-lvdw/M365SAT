# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz3133($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz3133"
		FindingName	     = "CIS Az 3.1.3.3 - Microsoft Endpoint Protection component status is not set to 'On'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Microsoft Defender for Endpoint integration brings comprehensive Endpoint Detection and Response (EDR) capabilities within Microsoft Defender for Cloud. This integration helps to spot abnormalities, as well as detect and respond to advanced attacks on endpoints monitored by Microsoft Defender for Cloud."
		Remediation	     = "Navigate to the PowerShellScript link, select the subscription and under Settings & Monitoring toggle Endpoint Protection to On."
		PowerShellScript = 'https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/EnvironmentSettings'
		DefaultValue	 = "Off"
		ExpectedValue    = "On"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Understand endpoint detection and response'; 'URL' = 'https://learn.microsoft.com/en-in/azure/defender-for-cloud/integration-defender-for-endpoint?tabs=windows' },
		@{ 'Name' = 'ES-1: Use Endpoint Detection and Response (EDR)'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-identity-management#im-9-secure-user-access-to--existing-applications' },
		@{ 'Name' = 'ES-2: Use modern anti-malware software'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-endpoint-security#es-2-use-modern-anti-malware-software' })
	}
	return $inspectorobject
}

function Audit-CISAz3133
{
	try
	{
		# Actual Script
		$AzSecuritySetting = Get-AzSecuritySetting | Select-Object name,enabled |where-object {$_.name -eq "WDATP"}
		
		# Validation
		if ($AzSecuritySetting.Enabled -eq $False)
		{
			$finalobject = Build-CISAz3133($AzSecuritySetting.Enabled)
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
return Audit-CISAz3133