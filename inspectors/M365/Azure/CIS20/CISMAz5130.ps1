# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure 'Access reviews' for Guest Users are configured
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz5130($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz5130"
		FindingName	     = "CIS MAz 5.13 - Some Microsoft Defender Subscriptions are not Active or Enabled"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "5"
		Description	     = "Security teams can receive notifications of triggered alerts for atypical or suspicious activities, see how the organization's data in Microsoft 365 is accessed and used, suspend user accounts exhibiting suspicious activity, and require users to log back in to Microsoft 365 apps after an alert has been triggered"
		Remediation	     = "Use the PowerShell script to enable the Standard Pricing Tier for Microsoft Defender Subscriptions in Azure"
		PowerShellScript = 'Set-AzSecurityPricing -Name "{MicrosoftDefenderSubscriptionHERE}" -PricingTier "Standard"'
		DefaultValue	 = "Disabled"
		ExpectedValue    = "Enabled"
		ReturnedValue    = $findings
		Impact		     = "1"
		Likelihood	     = "5"
		RiskRating	     = "Medium"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Quickstart: Enable enhanced security features'; 'URL' = 'https://docs.microsoft.com/en-us/azure/defender-for-cloud/enable-enhanced-security' })
	}
	return $inspectorobject
}

Function Audit-CISMAz5130
{
	try
	{
		$MicrosoftDefenderSubscriptions = @()
		
		try
		{
			$Subscriptions = Get-AzSecurityPricing | Select-Object Name, PricingTier, FreeTrialRemainingTime
		}
		catch
		{
			$Subscriptions = $null
		}
		
		if ($Subscriptions -ne $null)
		{
			foreach ($Subscription in $Subscriptions)
			{
				if ($Subscription.PricingTier -ne "Standard")
				{
					$MicrosoftDefenderSubscriptions += "$($Subscription.Name) is not Standard, but $($Subscription.PricingTier)"
				}
			}
		}
		
		if ($MicrosoftDefenderSubscriptions.Count -igt 0)
		{
			$MicrosoftDefenderSubscriptions | Format-Table -AutoSize | Out-File "$path\CISMAz5130MSDefenderSubscriptions.txt"
			$object = Build-CISMAz5130($MicrosoftDefenderSubscriptions)
			return $object
		}
		return $null
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
Return Audit-CISMAz5130