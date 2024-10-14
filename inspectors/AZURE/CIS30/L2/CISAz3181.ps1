# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz3181($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz3181"
		FindingName	     = "CIS Az 3.1.8.1 - Microsoft Defender for Key Vault Is Set to 'Off'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Enabling Microsoft Defender for Key Vault allows for greater defense-in-depth, with threat detection provided by the Microsoft Security Response Center (MSRC)."
		Remediation	     = "Use the PowerShell script to remediate the issue"
		PowerShellScript = 'Set-AzSecurityPricing -Name "AppServices" -PricingTier "Standard"'
		DefaultValue	 = "Off"
		ExpectedValue    = "On"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Security alerts and incidents'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview' },
		@{ 'Name' = 'LT-1: Enable threat detection capabilities'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-1-enable-threat-detection-capabilities' })
	}
	return $inspectorobject
}

function Audit-CISAz3181
{
	try
	{
		# Actual Script
		$AzSecuritySetting = Get-AzSecurityPricing -Name "AppServices" | Select-Object Name,PricingTier
		
		# Validation
		if ($AzSecuritySetting.PricingTier -ne 'Standard')
		{
			$finalobject = Build-CISAz3181($AzSecuritySetting.PricingTier)
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
return Audit-CISAz3181