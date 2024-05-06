# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure That 'Subscription Entering AAD Directory' and 'Subscription Leaving AAD Directory' Is Set To 'Permit No One'
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz1240($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz1240"
		FindingName	     = "CIS Az 1.24 - 'Subscription Entering AAD Directory' and 'Subscription Leaving AAD Directory' Are Set to Everyone!"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "10"
		Description	     = "Permissions to move subscriptions in and out of Microsoft Entra ID must only be given to appropriate administrative personnel. A subscription that is moved into an Microsoft Entra ID directory may be within a folder to which other users have elevated permissions. This prevents loss of data or unapproved changes of the objects within by potential bad actors."
		Remediation	     = "Navigate to the URL in the PowerShell script to remediate this issue."
		PowerShellScript = 'https://portal.azure.com/#view/Microsoft_Azure_SubscriptionManagement/ManageSubscriptionPoliciesBlade'
		DefaultValue	 = "False"
		ExpectedValue    = "True"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Manage Azure subscription policies'; 'URL' = 'https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/manage-azure-subscription-policy' },
			@{ 'Name' = 'Associate or add an Azure subscription to your Microsoft Entra tenant'; 'URL' = 'https://learn.microsoft.com/en-us/entra/fundamentals/how-subscriptions-associated-directory' })
	}
	return $inspectorobject
}

function Audit-CISAz1240
{
	try
	{
		$SubscriptionSettings = @()
		# Actual Script
		$Setting1 = ((Invoke-AzRestMethod -Method GET -Path '/providers/Microsoft.Subscription/policies/default?api-version=2021-01-01-privatepreview').content | ConvertFrom-Json | Select-Object properties).properties.blockSubscriptionsLeavingTenant
		$Setting2 = ((Invoke-AzRestMethod -Method GET -Path '/providers/Microsoft.Subscription/policies/default?api-version=2021-01-01-privatepreview').content | ConvertFrom-Json | Select-Object properties).properties.blockSubscriptionsIntoTenant
		
		if ($Setting1 -eq $false)
		{
			$SubscriptionSettings += "blockSubscriptionsLeavingTenant: $($Setting1)"
		}
		if ($Setting2 -eq $false)
		{
			$SubscriptionSettings += "blockSubscriptionsIntoTenant: $($Setting2)"
		}
		
		if ($SubscriptionSettings.Count -igt 0)
		{
			$finalobject = Build-CISAz1240($SubscriptionSettings)
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
return Audit-CISAz1240