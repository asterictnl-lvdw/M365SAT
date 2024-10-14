# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz3191($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz3191"
		FindingName	     = "CIS Az 3.1.9.1 - Microsoft Defender for Resource Manager is Set to 'Off'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Scanning resource requests lets you be alerted every time there is suspicious activity in order to prevent a security threat from being introduced."
		Remediation	     = "Use the PowerShell script to remediate the issue"
		PowerShellScript = 'Set-AzSecurityPricing -Name "Arm" -PricingTier "Standard"'
		DefaultValue	 = "Off"
		ExpectedValue    = "On"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Connect your Azure subscriptions'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/connect-azure-subscription' },
		@{ 'Name' = 'Overview of Microsoft Defender for Resource Manager'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-resource-manager-introduction' },
		@{ 'Name' = 'Microsoft Defender for Cloud pricing'; 'URL' = 'https://azure.microsoft.com/en-us/pricing/details/defender-for-cloud/' },
		@{ 'Name' = 'Security alerts and incidents'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview' },
		@{ 'Name' = 'LT-1: Enable threat detection capabilities'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-1-enable-threat-detection-capabilities' })
	}
	return $inspectorobject
}

function Audit-CISAz3191
{
	try
	{
		# Actual Script
		$AzSecuritySetting = Get-AzSecurityPricing -Name "Arm" | Select-Object Name,PricingTier
		
		# Validation
		if ($AzSecuritySetting.PricingTier -ne 'Standard')
		{
			$finalobject = Build-CISAz3191($AzSecuritySetting.PricingTier)
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
return Audit-CISAz3191
