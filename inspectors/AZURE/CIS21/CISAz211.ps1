# Date: 25-1-2023
# Version: 1.0
# Benchmark: CISAz Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Checks Microsoft Defender Subscriptions
# Author: Leonardo van de Weteringh
# Applies to CIS 2.1.1 till 2.1.12

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz211($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz21x"
		FindingName	     = "CIS Az 2.1.x - Multiple Defender Subscriptions Not Compliant"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "1"
		Description	     = "Enabling Microsoft Defender allows for greater defense-in-depth, with threat detection provided by the Microsoft Security Response Center (MSRC)."
		Remediation	     = "Use the powershell command and replace SubScriptionName with the corresponding subscription which has a Free Pricing Tier at the moment."
		PowerShellScript = 'Set-AzSecurityPricing -Name "<SubscriptionName>" -PricingTier "Standard"'
		DefaultValue	 = "By default, Microsoft Defender plan is off (None) or set to Free"
		ExpectedValue    = "Standard"
		ReturnedValue    = "$findings"
		Impact		     = "1"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'PV-6: Rapidly and automatically remediate vulnerabilities'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-posture-vulnerability-management#pv-6-rapidly-and-automatically-remediate-vulnerabilities' },
			@{ 'Name' = 'Azure Pricing'; 'URL' = 'https://azure.microsoft.com/en-us/pricing/#product-pricing' },
		@{ 'Name' = 'IM-2: Protect identity and authentication systems'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-2-protect-identity-and-authentication-systems' })
	}
	return $inspectorobject
}

function Audit-CISAz211
{
	try
	{
		# Actual Script
		$MicrosoftDefenderSubscriptions = @("VirtualMachines", "AppServices", "SqlServers", "SqlServerVirtualMachines", "OpenSourceRelationalDatabases", "CosmosDbs", "StorageAccounts", "ContainerRegistry", "Containers", "KeyVaults","DNS","Arm")
		$AffectedMicrosoftDefenderSubscriptions = @()
		
		foreach ($subscription in $MicrosoftDefenderSubscriptions)
		{
			$SubscriptionStatus = Get-AzSecurityPricing -Name "$($subscription)" | Select-Object Name, PricingTier
			if ($SubscriptionStatus.PricingTier -match 'Free')
			{
				$AffectedMicrosoftDefenderSubscriptions += "$($SubscriptionStatus.Name) has a $($SubscriptionStatus.PricingTier) subscription"
			}
		}
		
		# Validation
		if ($AffectedMicrosoftDefenderSubscriptions.count -igt 0)
		{
			$finalobject = Build-CISAz211($AffectedMicrosoftDefenderSubscriptions)
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
return Audit-CISAz211