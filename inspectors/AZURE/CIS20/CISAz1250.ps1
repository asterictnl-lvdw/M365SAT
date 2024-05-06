# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure That 'Subscription Entering AAD Directory' and 'Subscription Leaving AAD Directory' Is Set To 'Permit No One'
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz1250($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz1250"
		FindingName	     = "CIS Az 1.25 - 'Subscription Entering AAD Directory' and 'Subscription Leaving AAD Directory' Are Set to Everyone!"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "10"
		Description	     = "Permissions to move subscriptions in and out of Azure Active Directory must only be given to appropriate administrative personnel. A subscription that is moved into an Azure Active Directory may be within a folder to which other users have elevated permissions. This prevents loss of data or unapproved changes of the objects within by potential bad actors."
		Remediation	     = "You can change the settings in the URL written in PowerShellScript."
		PowerShellScript = 'https://portal.azure.com/#view/Microsoft_Azure_SubscriptionManagement/ManageSubscriptionPoliciesBlade'
		DefaultValue	 = "False"
		ExpectedValue    = "True"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Azure custom roles'; 'URL' = 'https://learn.microsoft.com/en-us/azure/role-based-access-control/custom-roles' },
			@{ 'Name' = 'Quickstart: Check access for a user to Azure resources'; 'URL' = 'https://learn.microsoft.com/en-us/azure/role-based-access-control/check-access' })
	}
	return $inspectorobject
}

function Audit-CISAz1250
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
			$finalobject = Build-CISAz1250($SubscriptionSettings)
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
return Audit-CISAz1250