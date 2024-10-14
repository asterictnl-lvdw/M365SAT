# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz31016($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz31016"
		FindingName	     = "CIS Az 3.1.16 - Microsoft Defender for DNS is Set to 'Off'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "DNS lookups within a subscription are scanned and compared to a dynamic list of websites that might be potential security threats. These threats could be a result of a security breach within your services, thus scanning for them could prevent a potential security threat from being introduced."
		Remediation	     = "Use the PowerShell script to remediate the issue"
		PowerShellScript = 'Set-AzSecurityPricing -Name "DNS" -PricingTier "Standard"'
		DefaultValue	 = "Off"
		ExpectedValue    = "On"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Connect your Azure subscriptions'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/connect-azure-subscription' },
		@{ 'Name' = 'Azure security baseline for Azure DNS'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/baselines/azure-dns-security-baseline' },
		@{ 'Name' = 'Microsoft Defender for Cloud pricing'; 'URL' = 'https://azure.microsoft.com/en-us/pricing/details/defender-for-cloud/' },
		@{ 'Name' = 'Security alerts and incidents'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview' },
		@{ 'Name' = 'Respond to Microsoft Defender for DNS alerts'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-dns-alerts' },
		@{ 'Name' = 'NS-10: Ensure Domain Name System (DNS) security'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-network-security#ns-10-ensure-domain-name-system-dns-security' },
		@{ 'Name' = 'LT-1: Enable threat detection capabilities'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-1-enable-threat-detection-capabilities' })
	}
	return $inspectorobject
}

function Audit-CISAz31016
{
	try
	{
		# Actual Script
		$AzSecuritySetting = Get-AzSecurityPricing -Name "DNS" | Select-Object Name,PricingTier
		
		# Validation
		if ($AzSecuritySetting.PricingTier -ne 'Standard')
		{
			$finalobject = Build-CISAz31016($AzSecuritySetting.PricingTier)
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
return Audit-CISAz31016