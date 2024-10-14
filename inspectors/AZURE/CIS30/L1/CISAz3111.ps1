# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz3111($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz3111"
		FindingName	     = "CIS Az 3.1.1.1 - Auto provisioning of 'Log Analytics agent for Azure VMs' is Set to 'Off'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "When Log Analytics agent for Azure VMs is turned on, Microsoft Defender for Cloud provisions the Microsoft Monitoring Agent on all existing supported Azure virtual machines and any new ones that are created. The Microsoft Monitoring Agent scans for various security-related configurations and events such as system updates, OS vulnerabilities, endpoint protection, and provides alerts."
		Remediation	     = "Navigate to the PowerShellScript link, select the subscription and under Settings & Monitoring you toggle Log Analytics agent to On."
		PowerShellScript = 'https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/EnvironmentSettings'
		DefaultValue	 = "On"
		ExpectedValue    = "On"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Microsoft Defender for Cloud data security'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/data-security' },
		@{ 'Name' = 'How does Defender for Cloud collect data?'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/monitoring-components' },
		@{ 'Name' = 'LT-5: Centralize security log management and analysis'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-5-centralize-security-log-management-and-analysis' },
		@{ 'Name' = 'LT-3: Enable logging for security investigation'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation' },
		@{ 'Name' = 'IR-2: Preparation - setup incident notification'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-incident-response#ir-2-preparation---setup-incident-notification' })
	}
	return $inspectorobject
}

function Audit-CISAz3111
{
	try
	{
		# Actual Script
		$AutoProvisioningSetting = Get-AzSecurityAutoProvisioningSetting | Select-Object Name, AutoProvision
		
		# Validation
		if ($AutoProvisioningSetting.AutoProvision -eq 'Off')
		{
			$finalobject = Build-CISAz3111($AutoProvisioningSetting.AutoProvision)
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
return Audit-CISAz3111